package org.stratumproject.fabric.tna.slicing;

import org.onlab.packet.EthType;
import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;
import org.onlab.packet.VlanId;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.HostId;
import org.onosproject.net.HostLocation;
import org.onosproject.net.config.ConfigException;
import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.config.basics.BasicHostConfig;
import org.onosproject.net.config.basics.SubjectFactories;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.stratumproject.fabric.tna.slicing.api.SlicingConfig;
import org.stratumproject.fabric.tna.slicing.api.SlicingProviderService;
import org.stratumproject.fabric.tna.slicing.api.SlicingService;
import org.stratumproject.fabric.tna.slicing.api.TrafficClass;

import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.stream.Collectors;

import static java.util.concurrent.Executors.newSingleThreadScheduledExecutor;
import static org.onlab.util.Tools.groupedThreads;
import static org.stratumproject.fabric.tna.PipeconfLoader.APP_NAME;

@Component(immediate = true, service = {
        NetcfgSlicingProvider.class,
})
public class NetcfgSlicingProvider {

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected SlicingService slicingService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected SlicingProviderService slicingProviderService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigRegistry netcfgRegistry;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigService netcfgService;

    private ExecutorService eventExecutor;

    private final Logger log = LoggerFactory.getLogger(getClass());
    private final InternalNetworkConfigListener netcfgListener =
            new InternalNetworkConfigListener();

    private final ConfigFactory<ApplicationId, SlicingConfig> configFactory = new ConfigFactory<>(
            SubjectFactories.APP_SUBJECT_FACTORY, SlicingConfig.class, "slicing") {
        @Override
        public SlicingConfig createConfig() {
            return new SlicingConfig();
        }
    };

    @Activate
    protected void activate() {
        eventExecutor = newSingleThreadScheduledExecutor(groupedThreads("fabric-tna-slicing-netcfg", "events-%d", log));
        netcfgRegistry.registerConfigFactory(configFactory);
        netcfgRegistry.addListener(netcfgListener);

        readInitialConfig();

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        netcfgRegistry.removeListener(netcfgListener);
        eventExecutor.shutdown();
        netcfgRegistry.unregisterConfigFactory(configFactory);

        log.info("Stopped");
    }

    private void readInitialConfig() {

    }

    private void configAdded(SlicingConfig config) throws ConfigException {
        config.slices().forEach(sliceDescr -> {
            slicingProviderService.addSlice(sliceDescr.id());
            sliceDescr.tcDescriptions().forEach(tcDescr -> {
                slicingProviderService.addTrafficClass(sliceDescr.id(), tcDescr);
            });
        });
    }

    private void configRemoved() throws ConfigException {
        slicingService.getSlices().forEach(sliceId -> {
            slicingService.getTrafficClasses(sliceId).forEach(tc -> {
                if (tc.equals(TrafficClass.BEST_EFFORT)) {
                    return;
                }
                slicingProviderService.removeTrafficClass(sliceId, tc);
            });
            slicingProviderService.removeSlice(sliceId);
        });
    }

    private void configUpdated(SlicingConfig config) {
        // TODO: not supported for now? Remove all, then re-add
        //  Maybe add CLI command to wipe out all slicing state? Including classifier flows?
        // Remove removed slices

        // Add added slices

        // Add/remove tcs
    }

    // TODO: listen for netcfg, register slices/tcs with slicingProviderService
    // Use reconciliation to notify errors periodically

    /*
    Get event
    Work distribution? Checl netcfg link provider
    Compare slicing description event with current store state
    Should we check diff? netcfg generates event only if diff

    Reconciliation
    Every 30 seconds
    Gett current netcfg
    Diff with slicingmanager store
    If diff -> correct, log errors

    Example errors could be classifier flows still using the slice or TC
    Or default TCs, but we can change the default TC...
     */

    // New slicing config
    // Remove slicing config -> Error
    // Add slice to existing config -> Error
    // Remove slice from existing config -> Error
    //

    private class InternalNetworkConfigListener implements NetworkConfigListener {
        @Override
        public void event(NetworkConfigEvent event) {

            switch (event.type()) {
                case CONFIG_ADDED:
                    // TODO: add slices and tcs
                    break;
                case CONFIG_UPDATED:
                    // TODO: some slices / tcs have been updated
=                    break;
                case CONFIG_REMOVED:
                    // TODO: remove all slices and tcs
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
