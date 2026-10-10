/* SPDX-License-Identifier: MIT */
import { handleLambdaHttpApiV2 } from "../gateway/index.mjs";

export const handler = async (event) => handleLambdaHttpApiV2(event, process.env);
