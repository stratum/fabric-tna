package org.stratumproject.fabric.tna.slicing;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.stratumproject.fabric.tna.slicing.api.SlicingProviderService;

@Component(immediate = true, service = {
        NetcfgSlicingProvider.class,
})
public class NetcfgSlicingProvider {

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected SlicingProviderService slicingProviderService;

    // TODO: listen for netcfg, register slices/tcs with slicingProviderService

}
