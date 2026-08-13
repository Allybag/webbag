FetchContent_Declare(
    glaze
    GIT_REPOSITORY https://github.com/stephenberry/glaze.git
    GIT_TAG        v7.9.1  # August 2026 latest stable version
    GIT_SHALLOW    TRUE
)

FetchContent_MakeAvailable(glaze)
