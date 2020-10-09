// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.behaviour.traceable;

import org.onlab.packet.MplsLabel;
import org.onlab.packet.VlanId;
import org.onosproject.core.GroupId;
import org.onosproject.net.PipelineTraceableMetadata;
import org.onosproject.net.PortNumber;

import java.util.Objects;

/**
 * Stores traceable fabric metadata.
 */
public final class FabricTraceableMetadata implements PipelineTraceableMetadata {

    // Fwd types constants
    public static final byte FWD_BRIDGING = 0x0;
    public static final byte FWD_MPLS = 0x1;
    public static final byte FWD_IPV4_UNICAST = 0x2;
    // By default we will do bridging
    private byte fwdType;
    // Metadata consumed by the Fwd and Next blocks
    private boolean skipFwd;
    private boolean skipNext;
    // Stores the bridged vlanId
    private VlanId vlanId;
    // Stores the next id
    private int nextId;
    // Stores the mpls label
    private MplsLabel mplsLabel;
    // Metadata consumed by the main traceable block
    private boolean copyToController;
    private boolean puntToController;
    // Group id - this is not technically needed but with it
    // we can catch potentially missing entries in the next tables
    private GroupId groupId;
    // To block forwarding on the input port
    private boolean isMulticast;
    // To match on the egress table
    private PortNumber outPort;

    /**
     * Builds a new traceable metadata.
     *
     * @param fwdtype the fwd type
     * @param skipfwd whether or not skip fwd step
     * @param skipnext whether or not skip next step
     * @param vlanid the vlan id
     * @param nextid the next id
     * @param mplslabel the mpls label
     * @param copytocontroller whether or not copy to the controller
     * @param punttocontroller whether or not punt to the controller
     * @param groupid group id
     * @param ismulticast whether or not is multicast traffic
     * @param outport egress port
     */
    private FabricTraceableMetadata(byte fwdtype, boolean skipfwd, boolean skipnext, VlanId vlanid, int nextid,
                                    MplsLabel mplslabel, boolean copytocontroller, boolean punttocontroller,
                                    GroupId groupid, boolean ismulticast, PortNumber outport) {
        fwdType = fwdtype;
        skipFwd = skipfwd;
        skipNext = skipnext;
        vlanId = vlanid;
        nextId = nextid;
        mplsLabel = mplslabel;
        copyToController = copytocontroller;
        puntToController = punttocontroller;
        groupId = groupid;
        isMulticast = ismulticast;
        outPort = outport;
    }

    /**
     * Returns the fwd type.
     *
     * @return the current fwd type
     */
    public byte getFwdType() {
        return fwdType;
    }

    /**
     * Returns the skip fwd metadata.
     *
     * @return the value of the metadata
     */
    public boolean isSkipFwd() {
        return skipFwd;
    }

    /**
     * Returns the skip next metadata.
     *
     * @return the value of the metadata
     */
    public boolean isSkipNext() {
        return skipNext;
    }

    /**
     * Gets the stored vlan id.
     *
     * @return the vlan id
     */
    public VlanId getVlanId() {
        return vlanId;
    }

    /**
     * Gets the stored next id.
     *
     * @return the next id
     */
    public int getNextId() {
        return nextId;
    }

    /**
     * Gets the stored mpls label.
     *
     * @return the mpls label
     */
    public MplsLabel getMplsLabel() {
        return mplsLabel;
    }

    /**
     * Returns the copy to controller metadata.
     *
     * @return the value of the metadata
     */
    public boolean isCopyToController() {
        return copyToController;
    }

    /**
     * Returns the punt to controller metadata.
     *
     * @return the value of the metadata
     */
    public boolean isPuntToController() {
        return puntToController;
    }

    /**
     * Returns the group id.
     *
     * @return the group id
     */
    public GroupId getGroupId() {
        return groupId;
    }

    /**
     * Returns the is multicast metadata.
     *
     * @return the value of the metadata
     */
    public boolean isMulticast() {
        return isMulticast;
    }

    public PortNumber getOutPort() {
        return outPort;
    }

    @Override
    public int hashCode() {
        return Objects.hash(fwdType, skipFwd, skipNext, vlanId, nextId, mplsLabel, copyToController, puntToController,
                groupId, isMulticast, outPort);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof FabricTraceableMetadata) {
            FabricTraceableMetadata that = (FabricTraceableMetadata) obj;
            return Objects.equals(this.fwdType, that.fwdType) &&
                    this.skipFwd == that.skipFwd &&
                    this.skipNext == that.skipNext &&
                    Objects.equals(this.vlanId, that.vlanId) &&
                    this.nextId == that.nextId &&
                    Objects.equals(this.mplsLabel, that.mplsLabel) &&
                    this.copyToController == that.copyToController &&
                    this.puntToController == that.puntToController &&
                    Objects.equals(this.groupId, that.groupId) &&
                    this.isMulticast == that.isMulticast &&
                    Objects.equals(this.outPort, that.outPort);
        }
        return false;
    }

    @Override
    public String toString() {
        return "FabricTraceableMetadata{" +
                "fwdType=" + fwdType +
                ", skipFwd=" + skipFwd +
                ", skipNext=" + skipNext +
                ", vlanId=" + vlanId +
                ", nextId=" + nextId +
                ", mplsLabel=" + mplsLabel +
                ", copyToController=" + copyToController +
                ", puntToController=" + puntToController +
                ", groupId=" + groupId +
                ", isMulticast=" + isMulticast +
                ", outPort=" + outPort +
                "}";
    }

    /**
     * Returns a new builder.
     *
     * @return an empty builder
     */
    public static FabricTraceableMetadata.Builder builder() {
        return new FabricTraceableMetadata.Builder();
    }

    /**
     * Returns a new builder initialized with the traceable metadata.
     *
     * @param traceableMetadata the metadata used for the initialization
     * @return an initialized builder
     */
    public static FabricTraceableMetadata.Builder builder(FabricTraceableMetadata traceableMetadata) {
        return new FabricTraceableMetadata.Builder(traceableMetadata);
    }

    /**
     * Builder of fabric traceable metadata.
     */
    public static final class Builder {
        private byte fwdType;
        private boolean skipFwd = false;
        private boolean skipNext = false;
        private VlanId vlanId = VlanId.NONE;
        private int nextId = -1;
        private MplsLabel mplsLabel = MplsLabel.mplsLabel(0);
        private boolean copyToController = false;
        private boolean puntToController = false;
        private GroupId groupId = GroupId.valueOf(-1);
        private boolean isMulticast = false;
        private PortNumber outPort = PortNumber.ANY;

        private Builder() {

        }

        private Builder(FabricTraceableMetadata traceableMetadata) {
            setFwdType(traceableMetadata.fwdType);
            if (traceableMetadata.skipFwd) {
                setSkipFwd();
            }
            if (traceableMetadata.skipNext) {
                setSkipNext();
            }
            setVlanId(traceableMetadata.vlanId.toShort());
            setNextId(traceableMetadata.nextId);
            setMplsLabel(traceableMetadata.mplsLabel.toInt());
            if (traceableMetadata.copyToController) {
                setCopyToController();
            }
            if (traceableMetadata.puntToController) {
                setPuntToController();
            }
            setGroupId(traceableMetadata.groupId.id());
            if (traceableMetadata.isMulticast) {
                setIsMulticast();
            }
            setOutPort(traceableMetadata.outPort);
        }

        /**
         * Sets the fwd type.
         *
         * @param fwdtype the fwd type
         * @return this builder
         */
        public Builder setFwdType(byte fwdtype) {
            fwdType = fwdtype;
            return this;
        }

        /**
         * Sets bridging fwd type.
         *
         * @return this builder
         */
        public Builder setBridgingFwdType() {
            this.fwdType = FWD_BRIDGING;
            return this;
        }

        /**
         * Sets mpls fwd type.
         *
         * @return this builder
         */
        public Builder setMplsFwdType() {
            this.fwdType = FWD_MPLS;
            return this;
        }

        /**
         * Sets ipv4 fwd type.
         *
         * @return this builder
         */
        public Builder setIPv4FwdType() {
            this.fwdType = FWD_IPV4_UNICAST;
            return this;
        }

        /**
         * Sets true skipFwd metadata.
         *
         * @return this builder
         */
        public Builder setSkipFwd() {
            skipFwd = true;
            return this;
        }

        /**
         * Sets true skipNext metadata.
         *
         * @return this builder
         */
        public Builder setSkipNext() {
            skipNext = true;
            return this;
        }

        /**
         * Sets the vlan id in the metadata.
         *
         * @param vlanid the vlan id
         * @return this builder
         */
        public Builder setVlanId(short vlanid) {
            vlanId = VlanId.vlanId(vlanid);
            return this;
        }

        /**
         * Sets the next id in the metadata.
         *
         * @param nextid the next id
         * @return this builder
         */
        public Builder setNextId(int nextid) {
            nextId = nextid;
            return this;
        }

        /**
         * Sets the mpls label in the metadata.
         *
         * @param mplslabel the mpls label
         * @return this builder
         */
        public Builder setMplsLabel(int mplslabel) {
            mplsLabel = MplsLabel.mplsLabel(mplslabel);
            return this;
        }

        /**
         * Sets true copyToController metadata.
         *
         * @return this builder
         */
        public Builder setCopyToController() {
            copyToController = true;
            return this;
        }

        /**
         * Sets true puntToController metadata.
         *
         * @return this builder
         */
        public Builder setPuntToController() {
            puntToController = true;
            return this;
        }

        /**
         * Sets the group id.
         *
         * @param groupid the group id
         * @return this builder
         */
        public Builder setGroupId(int groupid) {
            groupId = GroupId.valueOf(groupid);
            return this;
        }

        /**
         * Sets true isMulticast metadata.
         *
         * @return this builder
         */
        public Builder setIsMulticast() {
            isMulticast = true;
            return this;
        }

        /**
         * Sets the output port.
         *
         * @param outport the output port
         * @return this builder
         */
        public Builder setOutPort(PortNumber outport) {
            outPort = outport;
            return this;
        }

        /**
         * Builds a new pipeline traceable output.
         *
         * @return a pipeline traceable object
         */
        public FabricTraceableMetadata build() {
            return new FabricTraceableMetadata(fwdType, skipFwd, skipNext, vlanId, nextId, mplsLabel,
                    copyToController, puntToController, groupId, isMulticast, outPort);
        }


    }

}
