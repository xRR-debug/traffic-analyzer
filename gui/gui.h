// gui.h — графический интерфейс TrafficAnalyzer (Dear ImGui + Direct3D 11).
#pragma once

#include <string>
#include <vector>

// Точка входа GUI-режима. files — дампы из командной строки (загружаются
// сразу). Возвращает код выхода.
int RunGuiMain(const std::vector<std::string>& files);
