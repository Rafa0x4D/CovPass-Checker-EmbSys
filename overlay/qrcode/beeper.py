import pigpio
from time import sleep

# GPIO Pin for the Beeper (Buzzer / output)
BEEPER_GPIO = 18


def beep(count, duration, pause):
    # start pigpio and connect to localhost on port 8888
    pi = pigpio.pi('localhost',8888)
    
    # dutycycle -> poweroff
    pi.set_PWM_dutycycle(BEEPER_GPIO, 0)
    pi.set_PWM_frequency(BEEPER_GPIO, 4000)
    max_duty_cycle = 255
    duty_cycle = int(0.5 * max_duty_cycle)  # 50% off max duttycyles
    while count > 0:
        # Start Beeping for <duration> in Seconds
        pi.set_PWM_dutycycle(BEEPER_GPIO, duty_cycle)
        sleep(duration)
        
        # Stop Beeping for <pause> in Seconds
        pi.set_PWM_dutycycle(BEEPER_GPIO, 0)
        sleep(pause)
        count -= 1

    # stop pigpio
    pi.stop() 
    
    
if __name__ == '__main__':
    beep(1, 0.2, 0.2)
