from ptf import testutils

# Size for different headers
profile_name = testutils.test_param_get("profile")
if profile_name == "fabric":
    BMD_BYTES = 24
elif profile_name == "fabric-int":
    BMD_BYTES = 33
elif profile_name == "fabric-spgw":
    BMD_BYTES = 32
elif profile_name == "fabric-spgw-int":
    BMD_BYTES = 39
else:
    raise Exception(f"Invalid profile {profile_name}, cannot set BMD_BYTES")
