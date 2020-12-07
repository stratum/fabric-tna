// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-1.0

package org.stratumproject.fabric.tna;

import org.onosproject.core.CoreService;
import org.onosproject.net.behaviour.Pipeliner;
import org.onosproject.net.behaviour.inbandtelemetry.IntProgrammable;
import org.onosproject.net.pi.model.DefaultPiPipeconf;
import org.onosproject.net.pi.model.PiPipeconf;
import org.onosproject.net.pi.model.PiPipeconf.ExtensionType;
import org.onosproject.net.pi.model.PiPipeconfId;
import org.onosproject.net.pi.model.PiPipelineInterpreter;
import org.onosproject.net.pi.model.PiPipelineModel;
import org.onosproject.net.pi.service.PiPipeconfService;
import org.osgi.framework.FrameworkUtil;
import org.osgi.framework.wiring.BundleWiring;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.onosproject.p4runtime.model.P4InfoParser;
import org.onosproject.p4runtime.model.P4InfoParserException;
import org.slf4j.Logger;
import org.stratumproject.fabric.tna.behaviour.FabricIntProgrammable;
import org.stratumproject.fabric.tna.behaviour.FabricInterpreter;
import org.stratumproject.fabric.tna.behaviour.pipeliner.FabricPipeliner;

import java.io.File;
import java.io.FileNotFoundException;
import java.net.URL;
import java.util.Collection;
import java.util.Objects;
import java.util.stream.Collectors;

import static java.lang.String.format;
import static org.osgi.framework.wiring.BundleWiring.LISTRESOURCES_RECURSE;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * Component responsible for registering the fabric-tna pipeconf
 * at app activation.
 */
@Component(immediate = true)
public class PipeconfLoader {

    public static final String APP_NAME = "org.stratumproject.fabric-tna";

    private static Logger log = getLogger(PipeconfLoader.class);

    private static final String BASE_PIPECONF_ID = "org.stratumproject";
    private static final String P4C_OUT_PATH = "/p4c-out";
    // p4c-out/<profile>/<platform>
    private static final String P4C_RES_BASE_PATH = P4C_OUT_PATH + "/%s/%s/";
    private static final String SEP = File.separator;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private PiPipeconfService pipeconfService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private CoreService coreService;

    private Collection<PiPipeconf> pipeconfs;

    private static final String P4INFO_TXT = "p4info.txt";
    private static final String CPU_PORT_TXT = "cpu_port.txt";
    private static final String PIPELINE_CONFIG = "pipeline_config.pb.bin";

    private static final String INT_PROFILE_SUFFIX = "-int";
    private static final String FULL_PROFILE_SUFFIX = "-full";

    @Activate
    public void activate() {
        coreService.registerApplication(APP_NAME);
        // Registers all pipeconf at component activation.
        pipeconfs = buildAllPipeconfs();
        pipeconfs.forEach(pipeconfService::register);
        log.info("Started");
    }

    @Deactivate
    public void deactivate() {
        pipeconfs.stream()
                .map(PiPipeconf::id)
                .forEach(pipeconfService::unregister);
        pipeconfs = null;
        log.info("Stopped");
    }

    private Collection<PiPipeconf> buildAllPipeconfs() {
        return FrameworkUtil
                .getBundle(this.getClass())
                .adapt(BundleWiring.class)
                // List all resource files in /p4c-out
                .listResources(P4C_OUT_PATH, "*", LISTRESOURCES_RECURSE)
                .stream()
                // Filter only directories
                .filter(name -> name.endsWith(SEP))
                // Derive profile, target, and platform and build pipeconf.
                .map(this::buildPipeconfFromPath)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    private PiPipeconf buildPipeconfFromPath(String path) {
        String[] pieces = path.split(SEP);
        // We expect a path of 3 elements, e.g.
        // p4c-out/<profile>/<platform>
        // p4c-out/fabric/mavericks_sde_9_2_0
        if (pieces.length != 3) {
            return null;
        }
        String profile = pieces[1];
        String platform = pieces[2];

        final DefaultPiPipeconf.Builder builder;
        try {
            builder = buildPipeconf(profile, platform);
        } catch (FileNotFoundException e) {
            log.warn("Got error when building the pipeconf with profile {} and platform {}: {}",
                    profile, platform, e.getMessage());
            return null;
        }

        builder.addBehaviour(PiPipelineInterpreter.class, FabricInterpreter.class)
                .addBehaviour(Pipeliner.class, FabricPipeliner.class);

        // Add IntProgrammable behaviour for INT-enabled profiles.
        if (profile.endsWith(INT_PROFILE_SUFFIX) ||
                profile.endsWith(FULL_PROFILE_SUFFIX)) {
            builder.addBehaviour(IntProgrammable.class, FabricIntProgrammable.class);
        }

        return builder.build();
    }

    private DefaultPiPipeconf.Builder buildPipeconf(String profile, String platform)
            throws FileNotFoundException {
        final URL tofinoPipelineConfigUrl = this.getClass().getResource(format(
                P4C_RES_BASE_PATH + PIPELINE_CONFIG, profile, platform));
        final URL p4InfoUrl = this.getClass().getResource(format(
                P4C_RES_BASE_PATH + P4INFO_TXT, profile, platform));
        final URL cpuPortUrl = this.getClass().getResource(format(
                P4C_RES_BASE_PATH + CPU_PORT_TXT, profile, platform));

        checkFileExists(tofinoPipelineConfigUrl, PIPELINE_CONFIG);
        checkFileExists(p4InfoUrl, P4INFO_TXT);
        checkFileExists(cpuPortUrl, CPU_PORT_TXT);

        return DefaultPiPipeconf.builder()
                .withId(new PiPipeconfId(format(
                        "%s.%s.%s", BASE_PIPECONF_ID, profile, platform)))
                .withPipelineModel(parseP4Info(p4InfoUrl))
                .addExtension(ExtensionType.RAW_DEVICE_CONFIG, tofinoPipelineConfigUrl)
                .addExtension(ExtensionType.P4_INFO_TEXT, p4InfoUrl)
                .addExtension(ExtensionType.CPU_PORT_TXT, cpuPortUrl);

    }

    private void checkFileExists(URL url, String name)
            throws FileNotFoundException {
        if (url == null) {
            throw new FileNotFoundException(name);
        }
    }

    private PiPipelineModel parseP4Info(URL p4InfoUrl) {
        try {
            return P4InfoParser.parse(p4InfoUrl);
        } catch (P4InfoParserException e) {
            // FIXME: propagate exception that can be handled by whoever is
            //  trying to build pipeconfs.
            throw new IllegalStateException(e);
        }
    }
}
