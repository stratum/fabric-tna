// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.behaviour.upf;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.onosproject.net.DeviceId;
import org.onosproject.net.config.basics.BasicDeviceConfig;

import java.io.IOException;
import java.io.InputStream;

public class TestUpfUtils {

    private static final String BASIC_CONFIG_KEY = "basic";

    public static BasicDeviceConfig getBasicConfig(DeviceId deviceId, String fileName) throws IOException {
        BasicDeviceConfig basicCfg = new BasicDeviceConfig();
        InputStream jsonStream = TestUpfUtils.class.getResourceAsStream(fileName);
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonNode = mapper.readTree(jsonStream);
        basicCfg.init(deviceId, BASIC_CONFIG_KEY, jsonNode, mapper, config -> {
        });
        return basicCfg;
    }
}
