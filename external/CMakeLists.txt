add_definitions(-w)

include(FetchContent)

FetchContent_Declare(
    seaplane
    GIT_REPOSITORY https://github.com/Allybag/seaplane
    GIT_TAG c547d1cb41eec3e1514cc2aa175b8415132c1e42
)
FetchContent_MakeAvailable(seaplane)

include(WolfSsl.cmake)
remove_definitions(-w)
