import serial
import time

# Set up the serial connection
ser = serial.Serial('/dev/ttyACM0', 9600)  # Replace 'COM3' with your port
time.sleep(2)  # Wait for the connection to establish

# Function to send a message and read the response
def send_message(message):
    ser.write((message + '\n').encode('utf-8'))  # Send the message
    time.sleep(1)  # Wait for Arduino to process
    while ser.in_waiting:  # Check if data is available
        response = ser.readline().decode('utf-8').strip()
        print('Arduino response:', response)

try:
    message = input("Enter a message to hash: ")
    send_message(message)
finally:
    ser.close()
