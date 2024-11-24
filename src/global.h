#ifndef GLOBAL_H
#define GLOBAL_H

#include <WString.h>

#define PIN_WAKE 18 // original: 5
#define PIN_DOORBELL 19
#define DOORBELL_BUTTON_PRESS_MS 500
#define WIFI_SIGNAL_INTERVAL 300000  // 5 minutes in milliseconds

extern void notifyClients(String message);
extern String getTimestampString();

#endif