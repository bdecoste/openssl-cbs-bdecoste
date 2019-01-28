workspace(name = "openssl_cbs")

load(
    "//:repositories.bzl",
    "abseil_repositories",
    "bsslwrapper_repositories",
)

abseil_repositories()
bsslwrapper_repositories()

new_local_repository(
    name = "openssl",
    path = "/usr/local/lib64/openssl",
    build_file = "openssl.BUILD"
)

