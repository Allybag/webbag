add_definitions(-w)

include(FetchContent)

FetchContent_Declare(
    seaplane
    GIT_REPOSITORY https://github.com/Allybag/seaplane
    GIT_TAG 0082963500249cefdfab3039d2083cb2da272141
)
FetchContent_MakeAvailable(seaplane)

include(WolfSsl.cmake)
remove_definitions(-w)
