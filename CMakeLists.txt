# CMakeLists.txt — сборка для macOS (Apple Silicon и Intel).
# Windows собирается как раньше, через TrafficAnalyzer.vcxproj — этот файл там не нужен.
#
#   brew install cmake glfw
#   cmake -B build
#   cmake --build build -j
#   ./build/TrafficAnalyzer              # окно
#   ./build/TrafficAnalyzer --console    # консольное меню
#
# Релизная сборка (как в CI): универсальный бинарник arm64 + x86_64 для
# macOS 11+, GLFW вшит — Homebrew не нужен:
#   cmake -B build -DTA_BUNDLED_GLFW=ON "-DCMAKE_OSX_ARCHITECTURES=arm64;x86_64" \
#         -DCMAKE_OSX_DEPLOYMENT_TARGET=11.0
#   cmake --build build -j
cmake_minimum_required(VERSION 3.20)
project(TrafficAnalyzer LANGUAGES C CXX)

if(NOT APPLE)
  message(FATAL_ERROR "CMakeLists.txt — только для macOS. На Windows открывайте TrafficAnalyzer.vcxproj.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release)
endif()
list(APPEND CMAKE_PREFIX_PATH /opt/homebrew /usr/local)   # Homebrew (arm64 / x86_64)

# --- бэкенды Dear ImGui (GLFW + OpenGL 3) ---------------------------------
# В репозитории лежит только ядро ImGui и бэкенды Windows. Бэкенды для macOS
# скачиваются при первой настройке — той же ревизии, что и ядро в gui/imgui.
set(IMGUI_COMMIT e19fea020f69e97e420f32d80f8f1dc7e829dc2c)
set(IMGUI_BACKENDS_DIR ${CMAKE_BINARY_DIR}/imgui_backends)
foreach(f imgui_impl_glfw.cpp imgui_impl_glfw.h
          imgui_impl_opengl3.cpp imgui_impl_opengl3.h imgui_impl_opengl3_loader.h)
  if(NOT EXISTS ${IMGUI_BACKENDS_DIR}/${f})
    message(STATUS "Скачиваю imgui/backends/${f}")
    file(DOWNLOAD
         https://raw.githubusercontent.com/ocornut/imgui/${IMGUI_COMMIT}/backends/${f}
         ${IMGUI_BACKENDS_DIR}/${f}
         STATUS st TLS_VERIFY ON)
    list(GET st 0 code)
    if(NOT code EQUAL 0)
      file(REMOVE ${IMGUI_BACKENDS_DIR}/${f})
      message(FATAL_ERROR "Не удалось скачать ${f}: ${st}")
    endif()
  endif()
endforeach()

# --- зависимости ----------------------------------------------------------
find_package(CURL REQUIRED)                 # libcurl из macOS SDK

# GLFW: по умолчанию из Homebrew (brew install glfw) — программа тогда работает
# только там, где он установлен. TA_BUNDLED_GLFW=ON собирает GLFW из исходников
# статически, той же архитектуры и минимальной версии macOS, что и программа:
# так собираются релизы (универсальный бинарник без Homebrew).
option(TA_BUNDLED_GLFW "GLFW из исходников, статически (для релизов)" OFF)
if(TA_BUNDLED_GLFW)
  include(FetchContent)
  set(GLFW_BUILD_DOCS     OFF CACHE BOOL "" FORCE)
  set(GLFW_BUILD_TESTS    OFF CACHE BOOL "" FORCE)
  set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
  set(GLFW_INSTALL        OFF CACHE BOOL "" FORCE)
  set(GLFW_LIBRARY_TYPE   STATIC CACHE STRING "" FORCE)
  FetchContent_Declare(glfw
    URL      https://github.com/glfw/glfw/releases/download/3.4/glfw-3.4.zip
    URL_HASH SHA256=b5ec004b2712fd08e8861dc271428f048775200a2df719ccf575143ba749a3e9)
  FetchContent_MakeAvailable(glfw)
  set(GLFW_TARGET glfw)
else()
  find_package(glfw3 3.3 QUIET)             # brew install glfw
  if(glfw3_FOUND)
    set(GLFW_TARGET glfw)
  else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(GLFW REQUIRED IMPORTED_TARGET glfw3)
    set(GLFW_TARGET PkgConfig::GLFW)
  endif()
endif()

# --- программа ------------------------------------------------------------
add_executable(TrafficAnalyzer
  analyzer.cpp
  detector_dpi.cpp
  detector_vpn.cpp
  report.cpp
  parser.cpp
  network.cpp
  ui.cpp
  capture.cpp
  config.cpp
  ip2proxy.cpp
  gui/gui.cpp
  gui/gui_main_mac.cpp
  gui/gui_log.cpp
  gui/gui_data.cpp
  gui/gui_rkn.cpp
  gui/imgui/imgui.cpp
  gui/imgui/imgui_draw.cpp
  gui/imgui/imgui_tables.cpp
  gui/imgui/imgui_widgets.cpp
  ${IMGUI_BACKENDS_DIR}/imgui_impl_glfw.cpp
  ${IMGUI_BACKENDS_DIR}/imgui_impl_opengl3.cpp
)

target_include_directories(TrafficAnalyzer PRIVATE
  ${CMAKE_SOURCE_DIR}
  ${CMAKE_SOURCE_DIR}/gui
  ${CMAKE_SOURCE_DIR}/gui/imgui
  ${IMGUI_BACKENDS_DIR}
)

target_compile_definitions(TrafficAnalyzer PRIVATE
  HAVE_NPCAP                # захват (режим 5) — через системный libpcap
  GL_SILENCE_DEPRECATION    # OpenGL на macOS помечен устаревшим, но работает
)

target_link_libraries(TrafficAnalyzer PRIVATE
  CURL::libcurl
  pcap
  ${GLFW_TARGET}
  "-framework OpenGL"
  "-framework ImageIO"
  "-framework CoreGraphics"
  "-framework CoreFoundation"
)

# встроенная картинка фона и пример настроек — рядом с программой
add_custom_command(TARGET TrafficAnalyzer POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          ${CMAKE_SOURCE_DIR}/gui/assets/anime_bg.jpg $<TARGET_FILE_DIR:TrafficAnalyzer>/anime_bg.jpg
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          ${CMAKE_SOURCE_DIR}/analyzer.ini.example $<TARGET_FILE_DIR:TrafficAnalyzer>/analyzer.ini.example
)
