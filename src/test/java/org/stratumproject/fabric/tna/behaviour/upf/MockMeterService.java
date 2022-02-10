// Copyright 2022-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0
package org.stratumproject.fabric.tna.behaviour.upf;

import com.google.common.collect.Sets;
import org.onosproject.net.DeviceId;
import org.onosproject.net.meter.DefaultMeter;
import org.onosproject.net.meter.Meter;
import org.onosproject.net.meter.MeterCellId;
import org.onosproject.net.meter.MeterRequest;
import org.onosproject.net.meter.MeterScope;
import org.onosproject.net.meter.MeterServiceAdapter;
import org.onosproject.net.pi.model.PiMeterId;
import org.onosproject.net.pi.runtime.PiMeterCellId;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

public class MockMeterService extends MeterServiceAdapter {
    final Set<Meter> meters = Sets.newHashSet();

    @Override
    public Meter submit(MeterRequest meter) {
        Meter addedMeter = DefaultMeter.builder()
                .forDevice(meter.deviceId())
                .fromApp(meter.appId())
                .withUnit(meter.unit())
                .withBands(meter.bands())
                .withCellId(PiMeterCellId.ofIndirect(PiMeterId.of(meter.scope().id()), meter.index().get()))
                .build();
        meters.add(addedMeter);
        return addedMeter;
    }

    @Override
    public void withdraw(MeterRequest meter, MeterCellId meterCellId) {
        Meter withDrawnMeter = DefaultMeter.builder()
                .forDevice(meter.deviceId())
                .fromApp(meter.appId())
                .withUnit(meter.unit())
                .withCellId(meterCellId)
                .withBands(meter.bands())
                .build();
        // TODO: does this work????
        meters.remove(withDrawnMeter);
    }

    @Override
    public Collection<Meter> getMeters(DeviceId deviceId) {
        return meters.stream()
                .filter(m -> m.deviceId().equals(deviceId))
                .collect(Collectors.toList());
    }

    @Override
    public Collection<Meter> getMeters(DeviceId deviceId, MeterScope scope) {
        return meters.stream()
                .filter(m -> m.deviceId().equals(deviceId) &&
                        ((PiMeterCellId) m.meterCellId()).meterId().equals(PiMeterId.of(scope.id())))
                .collect(Collectors.toList());
    }
}


