// Copyright (C) 2017-2018 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package lineage;

import (
  "strings"

  "android/soong/android"
  "android/soong/cc"
)

func init() {
  android.RegisterModuleType("camera_parameters_defaults", cameraParametersFactory)
}

func cameraParametersFactory() android.Module {
  module := cc.DefaultsFactory()
  android.AddLoadHook(module, cameraParameters)

  return module
}

func cameraParameters(ctx android.LoadHookContext) {
  type props struct {
    Include_dirs []string
    Whole_static_libs []string
  }

  p := &props{}
  p.Include_dirs, p.Whole_static_libs = globalDefaults(ctx)

  ctx.AppendProperties(p)
}

func globalDefaults(ctx android.BaseContext) ([]string, []string) {
  var includeDirs []string
  var staticLibs []string

  camera_headers_include_dir := ctx.DeviceConfig().TargetSpecificHeadersIncludeDir()
  if len(camera_headers_include_dir) > 0 {
    camera_headers_include_dir_list := strings.Fields(camera_headers_include_dir)
    for _, include_dir := range camera_headers_include_dir_list {
      includeDirs = append(includeDirs, include_dir)
    }
  }

  device_camera_parameters_lib := ctx.DeviceConfig().SpecificCameraParametersLibrary()
  if len(device_camera_parameters_lib) > 0 {
    staticLibs = append(staticLibs, device_camera_parameters_lib)
  }

  return includeDirs, staticLibs
}
