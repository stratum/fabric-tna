package org.stratumproject.fabric.tna.slicing;

import com.google.common.hash.Hashing;
import org.onlab.util.SharedExecutors;
import org.onosproject.net.config.ConfigException;
import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.config.SubjectFactory;
import org.onosproject.net.intent.WorkPartitionService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.stratumproject.fabric.tna.slicing.api.SliceConfig;
import org.stratumproject.fabric.tna.slicing.api.SliceId;
import org.stratumproject.fabric.tna.slicing.api.SlicingException;
import org.stratumproject.fabric.tna.slicing.api.SlicingProviderService;
import org.stratumproject.fabric.tna.slicing.api.SlicingService;

import static org.stratumproject.fabric.tna.Constants.APP_NAME_SLICING;

@Component(immediate = true)
public class NetcfgSlicingProvider {

    private static final Logger log = LoggerFactory.getLogger(NetcfgSlicingProvider.class);
    public static final String SLICES = "slices";

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected SlicingService slicingService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected SlicingProviderService slicingProviderService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigRegistry netcfgRegistry;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigService netcfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected WorkPartitionService workPartitionService;

    private final InternalNetworkConfigListener netcfgListener = new InternalNetworkConfigListener();

    public static final SubjectFactory<SliceId> SLICE_SUBJECT_FACTORY =
            new SubjectFactory<>(SliceId.class, SLICES) {
                @Override
                public SliceId createSubject(String key) {
                    return SliceId.of(Integer.parseInt(key));
                }

                @Override
                public String subjectKey(SliceId subject) {
                    return subject.toString();
                }
            };

    private final ConfigFactory<SliceId, SliceConfig> configFactory = new ConfigFactory<>(
            SLICE_SUBJECT_FACTORY, SliceConfig.class, SLICES) {
        @Override
        public SliceConfig createConfig() {
            return new SliceConfig();
        }
    };

    @Activate
    protected void activate() {
        netcfgRegistry.registerConfigFactory(configFactory);
        netcfgRegistry.addListener(netcfgListener);

        readInitialConfig();

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        netcfgRegistry.removeListener(netcfgListener);
        netcfgRegistry.unregisterConfigFactory(configFactory);

        log.info("Stopped");
    }

    private void readInitialConfig() {
        if (shouldDoWork()) {
            SharedExecutors.getSingleThreadExecutor().execute(() -> {
                log.info("Reading initial config");
                netcfgService.getSubjects(SliceId.class).forEach(sliceId -> {
                    SliceConfig config = netcfgService.getConfig(sliceId, SliceConfig.class);
                    if (config != null) {
                        addConfig(sliceId, config);
                    }
                });
            });
        }
    }

    private void addConfig(SliceId sliceId, SliceConfig config) {
        try {
            if (!sliceId.equals(SliceId.DEFAULT)) {
                try {
                    slicingProviderService.addSlice(sliceId);
                } catch (SlicingException e) {
                    log.error("Error adding slice", e);
                }
            }
            config.trafficClasses().forEach(tcDescr -> {
                try {
                    slicingProviderService.addTrafficClass(sliceId, tcDescr);
                } catch (SlicingException e) {
                    log.error("Error adding traffic class", e);
                }
            });
        } catch (ConfigException e) {
            // TODO: Consider adding a reconciliation thread to eventually apply
            //  the netcfg changes to the SlicingManager stores. Applies to
            //  configRemoved() as well.
            // SlicingExceptions might due to transient errors, e.g., ald slice
            // pending removal. We should keep retrying and logging the error to
            // signal the inconsistent state.
            log.error("Error in slice config", e);
        }
        log.info("Slicing config added");
    }

    private void removeConfig(SliceId sliceId, SliceConfig config) {
        try {
            if (sliceId.equals(SliceId.DEFAULT)) {
                // Cannot remove default slice. Must remove individual
                // traffic classes, leaving BEST_EFFORT in place.
                config.trafficClasses().forEach(tcDescr -> {
                    try {
                        slicingProviderService.removeTrafficClass(sliceId, tcDescr.trafficClass());
                    } catch (SlicingException e) {
                        log.error("Error removing traffic class from default slice", e);
                    }
                });
            } else {
                try {
                    slicingProviderService.removeSlice(sliceId);
                } catch (SlicingException e) {
                    log.error("Error removing slice", e);
                }
            }
        } catch (ConfigException e) {
            log.error("Error in slice config", e);
        }
        log.info("Slicing config removed");
    }

    private boolean shouldDoWork() {
        return workPartitionService.isMine(APP_NAME_SLICING,
                k -> Hashing.sha256().hashUnencodedChars(k).asLong());
    }

    private class InternalNetworkConfigListener implements NetworkConfigListener {
        @Override
        public void event(NetworkConfigEvent event) {
            switch (event.type()) {
                case CONFIG_ADDED:
                    if (event.config().isPresent() && shouldDoWork()) {
                        SharedExecutors.getSingleThreadExecutor().execute(
                                () -> addConfig((SliceId) event.subject(),
                                        (SliceConfig) event.config().get()));
                    }
                    break;
                case CONFIG_UPDATED:
                    log.error("Updating the slice config is not supported," +
                            "please remove and re-add the config");
                    break;
                case CONFIG_REMOVED:
                    if (event.prevConfig().isPresent() && shouldDoWork()) {
                        SharedExecutors.getSingleThreadExecutor().execute(
                                () -> removeConfig((SliceId) event.subject(),
                                        (SliceConfig) event.prevConfig().get()));
                    }
                    break;
                default:
                    break;
            }
        }

        @Override
        public boolean isRelevant(NetworkConfigEvent event) {
            return event.configClass().equals(SliceConfig.class);
        }
    }
}
