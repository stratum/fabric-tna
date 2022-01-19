package org.stratumproject.fabric.tna.slicing;

import com.google.common.hash.Hashing;
import org.onlab.util.SharedExecutors;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.config.ConfigException;
import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.config.basics.SubjectFactories;
import org.onosproject.net.intent.WorkPartitionService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.stratumproject.fabric.tna.PipeconfLoader;
import org.stratumproject.fabric.tna.slicing.api.SliceId;
import org.stratumproject.fabric.tna.slicing.api.SlicingConfig;
import org.stratumproject.fabric.tna.slicing.api.SlicingException;
import org.stratumproject.fabric.tna.slicing.api.SlicingProviderService;
import org.stratumproject.fabric.tna.slicing.api.SlicingService;

import static org.stratumproject.fabric.tna.Constants.APP_NAME;
import static org.stratumproject.fabric.tna.Constants.APP_NAME_SLICING;

@Component(immediate = true)
public class NetcfgSlicingProvider {

    private static final Logger log = LoggerFactory.getLogger(NetcfgSlicingProvider.class);

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

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

    // Unused. Forces activation after PipeconfLoader, so we can obtain an appId.
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PipeconfLoader pipeconfLoader;

    private ApplicationId appId;

    private final InternalNetworkConfigListener netcfgListener = new InternalNetworkConfigListener();
    private final ConfigFactory<ApplicationId, SlicingConfig> configFactory = new ConfigFactory<>(
            SubjectFactories.APP_SUBJECT_FACTORY, SlicingConfig.class, "slicing") {
        @Override
        public SlicingConfig createConfig() {
            return new SlicingConfig();
        }
    };

    @Activate
    protected void activate() {
        // App already registered by PipeconfLoader.
        appId = coreService.getAppId(APP_NAME);
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
            SlicingConfig config = netcfgService.getConfig(appId, SlicingConfig.class);
            if (config != null) {
                log.info("Reading initial config");
                SharedExecutors.getSingleThreadExecutor().execute(() -> addConfig(config));
            }
        }
    }

    private void addConfig(SlicingConfig config) {
        try {
            config.slices().forEach(sliceDescr -> {
                if (!sliceDescr.id().equals(SliceId.DEFAULT)) {
                    try {
                        slicingProviderService.addSlice(sliceDescr.id());
                    } catch (SlicingException e) {
                        log.error("Error adding slice", e);
                    }
                }
                sliceDescr.tcDescriptions().forEach(tcDescr -> {
                    try {
                        slicingProviderService.addTrafficClass(sliceDescr.id(), tcDescr);
                    } catch (SlicingException e) {
                        log.error("Error adding traffic class", e);
                    }
                });
            });
        } catch (ConfigException e) {
            // TODO: Consider adding a reconciliation thread to eventually apply
            //  the netcfg changes to the SlicingManager stores. Applies to
            //  configRemoved() as well.
            // SlicingExceptions might due to transient errors, e.g., ald slice
            // pending removal. We should keep retrying and logging the error to
            // signal the inconsistent state.
            log.error("Error in slicing config", e);
        }
        log.info("Slicing config added");
    }

    private void removeConfig(SlicingConfig config) {
        try {
            config.slices().forEach(sliceDescr -> {
                if (sliceDescr.id().equals(SliceId.DEFAULT)) {
                    // Cannot remove default slice. Must remove individual
                    // traffic classes, leaving BEST_EFFORT in place.
                    sliceDescr.tcDescriptions().forEach(tcDescr -> {
                        try {
                            slicingProviderService.removeTrafficClass(sliceDescr.id(), tcDescr.trafficClass());
                        } catch (SlicingException e) {
                            log.error("Error removing traffic class from default slice", e);
                        }
                    });
                } else {
                    try {
                        slicingProviderService.removeSlice(sliceDescr.id());
                    } catch (SlicingException e) {
                        log.error("Error removing slice", e);
                    }
                }
            });
        } catch (ConfigException e) {
            log.error("Error in slicing config", e);
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
                                () -> addConfig((SlicingConfig) event.config().get()));
                    }
                    break;
                case CONFIG_UPDATED:
                    log.error("Updating the slicing config is not supported," +
                            "please remove and re-add the config");
                    break;
                case CONFIG_REMOVED:
                    if (event.prevConfig().isPresent() && shouldDoWork()) {
                        SharedExecutors.getSingleThreadExecutor().execute(
                                () -> removeConfig((SlicingConfig) event.prevConfig().get()));
                    }
                    break;
                default:
                    break;
            }
        }

        @Override
        public boolean isRelevant(NetworkConfigEvent event) {
            return event.configClass().equals(SlicingConfig.class);
        }
    }
}
