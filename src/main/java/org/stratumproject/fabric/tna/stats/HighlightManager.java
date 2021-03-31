package org.stratumproject.fabric.tna.stats;

import com.google.common.collect.Sets;
import org.onlab.util.KryoNamespace;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.EdgeLink;
import org.onosproject.net.Host;
import org.onosproject.net.Link;
import org.onosproject.net.host.HostService;
import org.onosproject.net.link.LinkService;
import org.onosproject.store.serializers.KryoNamespaces;
import org.onosproject.store.service.DistributedSet;
import org.onosproject.store.service.Serializer;
import org.onosproject.store.service.SetEvent;
import org.onosproject.store.service.SetEventListener;
import org.onosproject.store.service.StorageService;
import org.onosproject.ui.UiExtensionService;
import org.onosproject.ui.UiTopoHighlighter;
import org.onosproject.ui.UiTopoHighlighterFactory;
import org.onosproject.ui.topo.BaseLink;
import org.onosproject.ui.topo.BaseLinkMap;
import org.onosproject.ui.topo.Highlights;
import org.onosproject.ui.topo.LinkHighlight;
import org.onosproject.ui.topo.Mod;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;

import java.text.CharacterIterator;
import java.text.StringCharacterIterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.onlab.util.Tools.groupedThreads;
import static org.onosproject.net.DefaultEdgeLink.createEdgeLinks;
import static org.slf4j.LoggerFactory.getLogger;

@Component(immediate = true, service = HighlightService.class)
public class HighlightManager implements HighlightService {
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected LinkService linkService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected StatisticService statisticService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected StorageService storageService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected UiExtensionService uiExtensionService;

    private static final Logger log = getLogger(HighlightManager.class);
    private static final String APP_NAME = "org.stratumproject.fabric.tna.highlight";
    private static final int BYTE_THRESHOLD = 100;
    private static final int PKT_THRESHOLD = 1;

    private ApplicationId appId;
    private final InternalHighlighter highlighter = new InternalHighlighter();
    private final UiTopoHighlighterFactory factory = () -> highlighter;

    // Distribited set storing current monitoring criteria
    private DistributedSet<HighlightKey> highlightStore;
    private SetEventListener<HighlightKey> highlightListener;
    private ExecutorService highLightExecutor;

    @Activate
    protected void activate() {
        appId = coreService.registerApplication(APP_NAME);

        KryoNamespace.Builder serializer = KryoNamespace.newBuilder()
                .register(KryoNamespaces.API)
                .register(HighlightKey.class)
                .register(Mod.class);

        highlightStore = storageService.<HighlightKey>setBuilder()
                .withName("fabric-tna-highlight")
                .withRelaxedReadConsistency()
                .withSerializer(Serializer.using(serializer.build()))
                .build().asDistributedSet();
        highlightListener = new InternalSetEventListener();
        highLightExecutor = Executors.newSingleThreadExecutor(
                groupedThreads("fabric-tna-highlight-event", "%d", log));
        highlightStore.addListener(highlightListener);

        uiExtensionService.register(factory);

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        highlightStore.removeListener(highlightListener);
        highLightExecutor.shutdown();

        highlightStore.forEach(highlighter::removeHighlighter);
        highlightStore.clear();

        uiExtensionService.unregister(factory);

        log.info("Stopped");
    }

    @Override
    public void addHighlight(int id, String name, Mod mod) {
        HighlightKey key = HighlightKey.builder()
                .withId(id)
                .withName(name)
                .withMod(mod)
                .build();
        highlightStore.add(key);
        log.info("Adding highlight {}", key);
    }

    @Override
    public void removeHighlight(int id, String name, Mod mod) {
        HighlightKey key = HighlightKey.builder()
                .withId(id)
                .withName(name)
                .withMod(mod)
                .build();
        highlightStore.remove(key);
        log.info("Removing highlight {}", key);
    }

    @Override
    public Set<HighlightKey> getHighlights() {
        return Set.copyOf(highlightStore);
    }

    private final class InternalHighlighter implements UiTopoHighlighter {
        private static final String NAME = "fabric-tna-highlighter";
        private final Set<HighlightKey> keys = Sets.newConcurrentHashSet();

        public void addHighlighter(HighlightKey key) {
            keys.add(key);
        }

        public void removeHighlighter(HighlightKey key) {
            keys.remove(key);
        }

        @Override
        public String name() {
            return NAME;
        }

        @Override
        public Highlights createHighlights() {
            Highlights highlights = new Highlights();
            BaseLinkMap linkMap = new BaseLinkMap();

            // Create a map of base bi-links from the set of active links first.
            for (Link link : linkService.getActiveLinks()) {
                linkMap.add(link);
            }

            for (Host host : hostService.getHosts()) {
                for (EdgeLink link : createEdgeLinks(host, false)) {
                    linkMap.add(link);
                }
            }

            // Now scan through the links and annotate them with desired highlights
            for (BaseLink link : linkMap.biLinks()) {
                log.debug("link={}", link);

                // Use to keep track on the dominant traffic on this link
                HighlightKey effectiveHighlightKey = null;
                long effectiveByteDiff = 0;
                long effectivePacketDiff = 0;
                long effectiveTimeMsDiff = 0;

                for (HighlightKey key : keys) {
                    Map<StatisticDataKey, StatisticDataValue> map = statisticService.getStats(key.id());

                    // TODO Refactor duplicated code
                    if (link.one().src().elementId() instanceof DeviceId) {
                        log.debug("link.one().src()={}", link.one().src());
                        StatisticDataKey dataKey;
                        StatisticDataValue dataValue;

                        dataKey = StatisticDataKey.builder()
                                .withDeviceId(link.one().src().deviceId())
                                .withPortNumber(link.one().src().port())
                                .withType(StatisticDataKey.Type.INGRESS)
                                .build();
                        dataValue = map.get(dataKey);
                        // Update only when current value is larger than previous largest value
                        if (dataValue != null &&
                                dataValue.byteDiff() >= BYTE_THRESHOLD &&
                                dataValue.packetDiff() >= PKT_THRESHOLD &&
                                dataValue.byteDiff() >= effectiveByteDiff) {
                            effectiveHighlightKey = key;
                            effectiveByteDiff = dataValue.byteDiff();
                            effectivePacketDiff = dataValue.packetDiff();
                            effectiveTimeMsDiff = dataValue.timeMsDiff();
                            log.debug("Update effective with {}, {}, {}", link, dataKey, dataValue);
                        }

                        dataKey = StatisticDataKey.builder()
                                .withDeviceId(link.one().src().deviceId())
                                .withPortNumber(link.one().src().port())
                                .withType(StatisticDataKey.Type.EGRESS)
                                .build();
                        dataValue = map.get(dataKey);
                        // Update only when current value is larger than previous largest value
                        if (dataValue != null &&
                                dataValue.byteDiff() >= BYTE_THRESHOLD &&
                                dataValue.packetDiff() >= PKT_THRESHOLD &&
                                dataValue.byteDiff() >= effectiveByteDiff) {
                            effectiveHighlightKey = key;
                            effectiveByteDiff = dataValue.byteDiff();
                            effectivePacketDiff = dataValue.packetDiff();
                            effectiveTimeMsDiff = dataValue.timeMsDiff();
                            log.debug("Update effective with {}, {}, {}", link, dataKey, dataValue);
                        }
                    }

                    if (link.one().dst().elementId() instanceof DeviceId) {
                        log.debug("link.one().dst()={}", link.one().src());
                        StatisticDataKey dataKey;
                        StatisticDataValue dataValue;

                        dataKey = StatisticDataKey.builder()
                                .withDeviceId(link.one().dst().deviceId())
                                .withPortNumber(link.one().dst().port())
                                .withType(StatisticDataKey.Type.INGRESS)
                                .build();
                        dataValue = map.get(dataKey);
                        // Update only when current value is larger than previous largest value
                        if (dataValue != null &&
                                dataValue.byteDiff() >= BYTE_THRESHOLD &&
                                dataValue.packetDiff() >= PKT_THRESHOLD &&
                                dataValue.byteDiff() >= effectiveByteDiff) {
                            effectiveHighlightKey = key;
                            effectiveByteDiff = dataValue.byteDiff();
                            effectivePacketDiff = dataValue.packetDiff();
                            effectiveTimeMsDiff = dataValue.timeMsDiff();
                            log.debug("Update effective with {}, {}, {}", link, dataKey, dataValue);
                        }

                        dataKey = StatisticDataKey.builder()
                                .withDeviceId(link.one().dst().deviceId())
                                .withPortNumber(link.one().dst().port())
                                .withType(StatisticDataKey.Type.EGRESS)
                                .build();
                        dataValue = map.get(dataKey);
                        // Update only when current value is larger than previous largest value
                        if (dataValue != null &&
                                dataValue.byteDiff() >= BYTE_THRESHOLD &&
                                dataValue.packetDiff() >= PKT_THRESHOLD &&
                                dataValue.byteDiff() >= effectiveByteDiff) {
                            effectiveHighlightKey = key;
                            effectiveByteDiff = dataValue.byteDiff();
                            effectivePacketDiff = dataValue.packetDiff();
                            effectiveTimeMsDiff = dataValue.timeMsDiff();
                            log.debug("Update effective with {}, {}, {}", link, dataKey, dataValue);
                        }
                    }
                }

                if (effectiveHighlightKey != null) {
                    Mod mod = effectiveHighlightKey.mod();
                    String label = String.format("%s / %s",
                            humanReadable(effectiveByteDiff * 1000 / effectiveTimeMsDiff, "Bps"),
                            humanReadable(effectivePacketDiff * 1000 / effectiveTimeMsDiff, "pps"));
                    highlights.add(new LinkHighlight(link.linkId(), LinkHighlight.Flavor.PRIMARY_HIGHLIGHT)
                            .addMod(mod)
                            .setLabel(label)
                    );
                    log.debug("Highlight link {} with {} and {}", link, mod, label);
                }
            }
            return highlights;
        }
    }

    // TODO Move this to org.onlab.util.Bandwidth
    /**
     * Convert number to a human readable format with given suffix.
     *
     * @param number number to be converted, e.g. 1000
     * @param suffix suffix string, e.g. Bps
     * @return human readable number, e.g. 1 KBps
     */
    private String humanReadable(long number, String suffix) {
        if (-1000 < number && number < 1000) {
            return number + " " + suffix;
        }
        CharacterIterator ci = new StringCharacterIterator("KMGTPE");
        while (number <= -999_950 || number >= 999_950) {
            number /= 1000;
            ci.next();
        }
        return String.format("%.1f %c%s", number / 1000.0, ci.current(), suffix);
    }

    private class InternalSetEventListener implements SetEventListener<HighlightKey> {
        @Override
        public void event(SetEvent<HighlightKey> event) {
            highLightExecutor.submit(() -> {
                log.debug("Processing event {}", event);
                switch (event.type()) {
                    case ADD:
                        highlighter.addHighlighter(event.entry());
                        break;
                    case REMOVE:
                        highlighter.removeHighlighter(event.entry());
                        break;
                    default:
                        break;
                }
            });

        }
    }
}