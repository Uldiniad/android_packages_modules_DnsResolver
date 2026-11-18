/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#pragma once

/*
 * This value should not be changed.
 * It's a flag used in both DnsProxyListener.cpp and NetdClient.cpp
 * to identify if bypassing DoT is available.
 * This flag must be kept in sync with the Network#getNetIdForResolv() usage.
 */
#define NETID_USE_LOCAL_NAMESERVERS 0x80000000

/*
 * "foruid <uid>", which NetdClient sends ahead of a request on the same connection when the
 * thread works for an app, as TrafficStats#setThreadStatsUid marks it. The request then counts as
 * that app's, if the caller may charge traffic to other apps. It gets no reply of its own.
 */
#define DNSPROXYD_FOR_UID "foruid"
