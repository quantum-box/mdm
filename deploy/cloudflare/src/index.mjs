/* SPDX-License-Identifier: MIT */
import { handleCloudflareRequest } from "../../gateway/index.mjs";

export default {
  async fetch(request, env) {
    return handleCloudflareRequest(request, env);
  },
};
