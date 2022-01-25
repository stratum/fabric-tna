// Copyright 2022-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
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

import static java.lang.String.format;
import static org.stratumproject.fabric.tna.Constants.APP_NAME;
import static org.stratumproject.fabric.tna.Constants.APP_NAME_SLICING;

/**
 * Slicing provider that uses network config to discover slices.
 */
@Component(immediate = true)
// TODO: add actual provider infrastructure by extending AbstractProvider
//  and by making SlicingProviderService extend ONOS's ProviderService.
// This will be useful when we will have multiple providers, e.g., to handle
// dynamic provisioning of slices (including device queue configuration).
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
    protected WorkPartitionService workPartitionService;

    // Unused. Forces activation after PipeconfLoader, so we can obtain an appId.
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PipeconfLoader pipeconfLoader;

    private ApplicationId appId;

    private final InternalNetworkConfigListener netcfgListener = new InternalNetworkConfigListener();
    private final ConfigFactory<ApplicationId, SlicingConfig> configFactory = new ConfigFactory<>(
            SubjectFactories.APP_SUBJECT_FACTORY, SlicingConfig.class, SlicingConfig.CONFIG_KEY) {
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
        execute(() -> {
            if (shouldDoWork()) {
                SlicingConfig config = netcfgRegistry.getConfig(appId, SlicingConfig.class);
                if (config != null) {
                    log.info("Reading initial config");
                    addConfig(config);
                }
            }
        }, "reading initial config");
    }

    private void addConfig(SlicingConfig config) {
        try {
            config.slices().forEach(sliceDescr -> {
                if (!sliceDescr.id().equals(SliceId.DEFAULT)) {
                    try {
                        slicingProviderService.addSlice(sliceDescr.id());
                    } catch (SlicingException e) {
                        // TODO: Consider adding a reconciliation thread to eventually apply
                        //  the netcfg changes to the SlicingManager stores. Applies to
                        //  other instance of SlicingException catch.
                        // SlicingExceptions might due to transient errors, e.g., old slice
                        // pending removal. We should keep retrying and logging the error to
                        // signal the inconsistent state.
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
        // Partitioning on a constant (APP_NAME_SLICING) will cause all events
        // to always be handled by the same instance, unless that instance
        // fails. We could consider a more load balanced strategy where work is
        // partitioned based on slice IDs. However, the performance gain will
        // likely be negligible, at the expense of introducing additional
        // complexity. Netcfg events are infrequent and lightweight (just a
        // handful of slices to update), it seems ok to have just one instance
        // handle updates for all slices.
        return workPartitionService.isMine(APP_NAME_SLICING,
                k -> Hashing.sha256().hashUnencodedChars(k).asLong());
    }

    private class InternalNetworkConfigListener implements NetworkConfigListener {
        @Override
        public void event(NetworkConfigEvent event) {
            execute(() -> {
                if (!shouldDoWork()) {
                    return;
                }
                switch (event.type()) {
                    case CONFIG_ADDED:
                        if (event.config().isPresent()) {
                            addConfig((SlicingConfig) event.config().get());
                        }
                        break;
                    case CONFIG_UPDATED:
                        log.error("Updating the slicing config is not supported," +
                                "please remove and re-add the config");
                        break;
                    case CONFIG_REMOVED:
                        if (event.prevConfig().isPresent()) {
                            removeConfig((SlicingConfig) event.prevConfig().get());
                        }
                        break;
                    default:
                        break;
                }
            }, format("handling %s event", event.type()));
        }

        @Override
        public boolean isRelevant(NetworkConfigEvent event) {
            return event.configClass().equals(SlicingConfig.class);
        }
    }

    private void execute(Runnable runnable, String taskDescription) {
        // Using the shared executor might introduce delay in events processing.
        // However, config is pushed infrequently (mostly at startup) and it's
        // not critical to apply that immediately.
        SharedExecutors.getSingleThreadExecutor().execute(() -> {
            try {
                runnable.run();
            } catch (Throwable e) {
                log.error("Error while " + taskDescription, e);
            }
        });
    }
}
