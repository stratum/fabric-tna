// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.opencord.fabric.tofino;

import org.onosproject.core.CoreService;
import org.onosproject.net.pi.model.DefaultPiPipeconf;
import org.onosproject.net.pi.model.PiPipeconf;
import org.onosproject.net.pi.model.PiPipeconf.ExtensionType;
import org.onosproject.net.pi.model.PiPipeconfId;
import org.onosproject.net.pi.service.PiPipeconfService;
import org.onosproject.pipelines.fabric.FabricPipeconfService;
import org.osgi.framework.FrameworkUtil;
import org.osgi.framework.wiring.BundleWiring;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;

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
 * Component responsible for registering Tofino-specific versions
 * of the fabric pipeconf at app activation.
 */
@Component(immediate = true)
public class PipeconfLoader {

    private static final String APP_NAME = "org.opencord.fabric-tofino";

    private static Logger log = getLogger(PipeconfLoader.class);

    private static final String BASE_PIPECONF_ID = "org.opencord";
    private static final String P4C_OUT_PATH = "/p4c-out";
    // p4c-out/<profile>/<platform>
    private static final String P4C_RES_BASE_PATH = P4C_OUT_PATH + "/%s/%s/%s/";
    private static final String SEP = File.separator;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private PiPipeconfService pipeconfService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private FabricPipeconfService fabricPipeconfService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private CoreService coreService;

    private Collection<PiPipeconf> pipeconfs;

    private static final String TOFINO = "tofino";
    private static final String P4INFO_TXT = "p4info.txt";
    private static final String CPU_PORT_TXT = "cpu_port.txt";
    private static final String TOFINO_BIN = "pipe/tofino.bin";
    private static final String TOFINO_CTX_JSON = "pipe/context.json";


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
        // We expect a path of 4 elements, e.g.
        // p4c-out/<profile>/<target>/<platform>
        if (pieces.length != 4) {
            return null;
        }
        String profile = pieces[1];
        String target = pieces[2];
        String platform = pieces[3];

        if (TOFINO.equals(target)) {
            try {
                return tofinoPipeconf(profile, platform);
            } catch (FileNotFoundException e) {
                log.warn("Unable to build pipeconf at {} because file is missing: {}",
                        path, e.getMessage());
                return null;
            }
        }

        log.warn("Unknown target '{}', skipping pipeconf build at '{}'...",
                target, path);
        return null;
    }

    private PiPipeconf tofinoPipeconf(String profile, String platform)
            throws FileNotFoundException {
        final URL tofinoBinUrl = this.getClass().getResource(format(
                P4C_RES_BASE_PATH + TOFINO_BIN, profile, TOFINO, platform));
        final URL contextJsonUrl = this.getClass().getResource(format(
                P4C_RES_BASE_PATH + TOFINO_CTX_JSON, profile, TOFINO, platform));
        final URL p4InfoUrl = this.getClass().getResource(format(
                P4C_RES_BASE_PATH + P4INFO_TXT, profile, TOFINO, platform));
        final URL cpuPortUrl = this.getClass().getResource(format(
                P4C_RES_BASE_PATH + CPU_PORT_TXT, profile, TOFINO, platform));

        checkFileExists(tofinoBinUrl, TOFINO_BIN);
        checkFileExists(contextJsonUrl, TOFINO_CTX_JSON);
        checkFileExists(p4InfoUrl, P4INFO_TXT);
        checkFileExists(cpuPortUrl, CPU_PORT_TXT);

        final DefaultPiPipeconf.Builder builder = DefaultPiPipeconf.builder()
                .withId(new PiPipeconfId(format(
                        "%s.%s.tofino.%s", BASE_PIPECONF_ID, profile, platform)))
                .addExtension(ExtensionType.TOFINO_BIN, tofinoBinUrl)
                .addExtension(ExtensionType.TOFINO_CONTEXT_JSON, contextJsonUrl);

        return fabricPipeconfService.buildFabricPipeconf(
                builder, profile, p4InfoUrl, cpuPortUrl);
    }

    private void checkFileExists(URL url, String name)
            throws FileNotFoundException {
        if (url == null) {
            throw new FileNotFoundException(name);
        }
    }
}
