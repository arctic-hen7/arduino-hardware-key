#include <Crypto.h>
#include <BLAKE2b.h>
#include <string.h>
#include <EEPROM.h>

#define KEY_LENGTH BLAKE2b::HASH_SIZE
#define NUM_SLOTS EEPROM.length() / KEY_LENGTH
#define IDENTIFIER "arduino_hardware_key"

void generateKey(byte *buf) {
    for (size_t i = 0; i < KEY_LENGTH; i++) {
        // NOTE: Upper bound is exclusive!
        buf[i] = random(0, 256);
    }
}

// Computes the HMAC of the given string data using the given key, returning a
// hex string of the HMAC.
String hmac(String data, byte *key) {
    byte hash[BLAKE2b::HASH_SIZE];

    BLAKE2b blake;
    blake.resetHMAC(key, KEY_LENGTH);
    blake.update((const byte*)data.c_str(), data.length());
    blake.finalizeHMAC(key, KEY_LENGTH, hash, sizeof(hash));

    String hmac_str;
    for (size_t i; i < sizeof(hash); i++) {
        if (hash[i] < 16) {
            hmac_str += "0";
        }
        hmac_str += String(hash[i], HEX);
    }

    return hmac_str;
}

void processCommand(String input) {
    input.trim();

    if (input == "identify") {
        Serial.println(IDENTIFIER);
    } else if (input.startsWith("generate ")) {
        // Usage: `generate <slot-num>`
        byte slot = input.substring(9).toInt();
        if (slot > NUM_SLOTS) {
            Serial.println("error: invalid slot number");
            return;
        }

        // Generate a random key and write it to memory
        byte key[KEY_LENGTH];
        generateKey(key);
        EEPROM.put(slot * KEY_LENGTH, key);
        Serial.println("success: generated");
    } else if (input.startsWith("challenge ")) {
        // Usage: `challenge <slot-num> <data>`
        byte spaceAfterSlot = input.indexOf(' ', 10);
        if (spaceAfterSlot != -1) {
            byte slot = input.substring(10, spaceAfterSlot).toInt();
            String data = input.substring(spaceAfterSlot + 1);

            if (slot > NUM_SLOTS) {
                Serial.println("error: invalid slot number");
                return;
            }

            // Read the key from memory
            byte key[KEY_LENGTH];
            EEPROM.get(slot * KEY_LENGTH, key);

            // Check that there is actually a key there (do NOT let the user do
            // HMAC with empty key slots!)
            byte isFilled = 0;
            for (byte i = 0; i < KEY_LENGTH; i++) {
                if (key[i] != 0) {
                    isFilled = 1;
                    break;
                }
            }
            if (!isFilled) {
                Serial.println("error: no key in slot");
            }

            Serial.print("success: ");
            Serial.print(hmac(data, key));
            Serial.print("\n");
        } else {
            Serial.println("error: malformed command");
        }
    } else {
        Serial.println("error: unknown command");
    }
}

void setup() {
    randomSeed(analogRead(0));

    Serial.begin(9600);
    while (!Serial) { ; }
}

void loop() {
    if (Serial.available() > 0) {
        String command = Serial.readStringUntil('\n');
        processCommand(command);
    }
}
