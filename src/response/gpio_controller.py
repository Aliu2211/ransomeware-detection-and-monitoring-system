import logging
import threading
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Flag to check if running on Raspberry Pi
try:
    import RPi.GPIO as GPIO
    GPIO_AVAILABLE = True
except ImportError:
    GPIO_AVAILABLE = False
    logger.warning("RPi.GPIO module not found. Running in simulation mode.")

class GPIOController:
    """
    Controller for Raspberry Pi GPIO pins to provide physical alerts
    """
    def __init__(self):
        """Initialize the GPIO controller"""
        self.initialized = False
        
        # Define pins for different alert types
        self.pins = {
            'status_led': 17,   # Green LED for system status
            'alert_led': 27,    # Red LED for alerts
            'activity_led': 22  # Yellow LED for activity
        }
        
        # Initialize GPIO if available
        if GPIO_AVAILABLE:
            try:
                # Set GPIO mode
                GPIO.setmode(GPIO.BCM)
                
                # Setup pins as outputs
                for pin in self.pins.values():
                    GPIO.setup(pin, GPIO.OUT)
                    GPIO.output(pin, GPIO.LOW)  # Start with all LEDs off
                
                self.initialized = True
                logger.info("GPIO controller initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize GPIO: {str(e)}")
        else:
            logger.info("Running in GPIO simulation mode")
            self.initialized = True  # Simulate initialization
    
    def set_status_led(self, state):
        """
        Set the status LED state
        
        Args:
            state (bool): True to turn on, False to turn off
        """
        self._set_pin('status_led', state)
    
    def set_alert_led(self, state):
        """
        Set the alert LED state
        
        Args:
            state (bool): True to turn on, False to turn off
        """
        self._set_pin('alert_led', state)
    
    def set_activity_led(self, state):
        """
        Set the activity LED state
        
        Args:
            state (bool): True to turn on, False to turn off
        """
        self._set_pin('activity_led', state)
    
    def _set_pin(self, pin_name, state):
        """Set the state of a GPIO pin"""
        if not self.initialized:
            logger.warning(f"GPIO controller not initialized, can't set {pin_name}")
            return
            
        if pin_name not in self.pins:
            logger.error(f"Unknown pin name: {pin_name}")
            return
            
        pin = self.pins[pin_name]
        
        if GPIO_AVAILABLE:
            try:
                GPIO.output(pin, GPIO.HIGH if state else GPIO.LOW)
                logger.debug(f"Set {pin_name} (pin {pin}) to {'HIGH' if state else 'LOW'}")
            except Exception as e:
                logger.error(f"Error setting GPIO pin {pin}: {str(e)}")
        else:
            # Simulation mode
            logger.debug(f"SIMULATION: Set {pin_name} (pin {pin}) to {'HIGH' if state else 'LOW'}")
    
    def blink_led(self, pin_name, count=3, interval=0.5):
        """
        Blink an LED
        
        Args:
            pin_name (str): Name of the pin to blink
            count (int): Number of blinks
            interval (float): Interval between blinks in seconds
        """
        if not self.initialized:
            logger.warning(f"GPIO controller not initialized, can't blink {pin_name}")
            return
            
        # Start blinking in a separate thread to avoid blocking
        thread = threading.Thread(target=self._blink_thread, args=(pin_name, count, interval))
        thread.daemon = True
        thread.start()
    
    def _blink_thread(self, pin_name, count, interval):
        """Thread function to blink an LED"""
        for _ in range(count):
            self._set_pin(pin_name, True)
            time.sleep(interval)
            self._set_pin(pin_name, False)
            time.sleep(interval)
    
    def cleanup(self):
        """Clean up GPIO pins on shutdown"""
        if GPIO_AVAILABLE and self.initialized:
            try:
                # Turn off all LEDs
                for pin in self.pins.values():
                    GPIO.output(pin, GPIO.LOW)
                
                # Clean up GPIO
                GPIO.cleanup()
                logger.info("GPIO pins cleaned up")
            except Exception as e:
                logger.error(f"Error during GPIO cleanup: {str(e)}")

# Singleton instance
gpio_controller = None

def get_gpio_controller():
    """Get the singleton GPIO controller instance"""
    global gpio_controller
    if gpio_controller is None:
        gpio_controller = GPIOController()
    return gpio_controller