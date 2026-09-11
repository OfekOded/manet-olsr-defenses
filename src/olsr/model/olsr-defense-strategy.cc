/*
 * Copyright (c) 2024 NS-3 Security Extension Project
 *
 * Author: Oded Ofek <odedofek2@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "olsr-defense-strategy.h"
#include "ns3/log.h"

namespace ns3 {
namespace olsr {

NS_LOG_COMPONENT_DEFINE("OlsrDefenseStrategy");

NS_OBJECT_ENSURE_REGISTERED(OlsrDefenseStrategy);
NS_OBJECT_ENSURE_REGISTERED(OlsrDefenseNull);

TypeId
OlsrDefenseStrategy::GetTypeId(void)
{
  static TypeId tid = TypeId("ns3::olsr::OlsrDefenseStrategy")
    .SetParent<Object>()
    .SetGroupName("Olsr");
  return tid;
}

void
OlsrDefenseStrategy::DoDispose()
{
  Object::DoDispose();
}

TypeId
OlsrDefenseNull::GetTypeId(void)
{
  static TypeId tid = TypeId("ns3::olsr::OlsrDefenseNull")
    .SetParent<OlsrDefenseStrategy>()
    .SetGroupName("Olsr")
    .AddConstructor<OlsrDefenseNull>();
  return tid;
}

} 
} 
