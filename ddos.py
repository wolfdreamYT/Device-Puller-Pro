import curses
from scapy.all import IP, ICMP, send
import time
import socket
import threading
import random

def send_ping_packets(target, min_packet_size=64, max_packet_size=1500, min_delay=0.1, max_delay=1.0, count=1):
    """
    Sends ICMP ping packets with randomized sizes and delays.

    :param target: The IP address or hostname of the target.
    :param min_packet_size: Minimum packet size in bytes.
    :param max_packet_size: Maximum packet size in bytes.
    :param min_delay: Minimum delay between packets in seconds.
    :param max_delay: Maximum delay between packets in seconds.
    :param count: Number of packets to send (default 1).
    """
    try:
        for i in range(count):
            # Randomize packet size within the range
            packet_size = random.randint(min_packet_size, max_packet_size)
            if packet_size > 1500:
                packet_size = 1500
            payload_size = packet_size - 28  # Subtract the ICMP and IP header sizes
            payload = b"A" * payload_size

            # Create an ICMP Echo Request packet
            packet = IP(dst=target)/ICMP()/payload

            # Send the packet
            send(packet, verbose=False)
            print(f"Ping {i + 1}/{count} sent to {target} ({packet_size} bytes)")

            # Randomized delay
            delay = random.uniform(min_delay, max_delay)
            time.sleep(delay)

    except KeyboardInterrupt:
        print("\nPing operation interrupted by user.")
    except Exception as e:
        print(f"An error occurred: {e}")

def thread_function(target, min_packet_size, max_packet_size, min_delay, max_delay, count):
    send_ping_packets(target, min_packet_size, max_packet_size, min_delay, max_delay, count)

def curses_menu(screen):
    curses.curs_set(0)
    screen.clear()
    screen.bkgd(curses.color_pair(1))

    options = ["Start", "Exit"]
    current_option = 0

    while True:
        screen.clear()

        height, width = screen.getmaxyx()
        for idx, option in enumerate(options):
            x = width // 2 - len(option) // 2
            y = height // 2 - len(options) // 2 + idx
            if idx == current_option:
                screen.attron(curses.color_pair(2))
                screen.addstr(y, x, option)
                screen.attroff(curses.color_pair(2))
            else:
                screen.addstr(y, x, option)

        key = screen.getch()

        if key == curses.KEY_UP and current_option > 0:
            current_option -= 1
        elif key == curses.KEY_DOWN and current_option < len(options) - 1:
            current_option += 1
        elif key == curses.KEY_ENTER or key in [10, 13]:
            if options[current_option] == "Start":
                return "start"
            elif options[current_option] == "Exit":
                return "exit"

        screen.refresh()

def main():
    result = curses.wrapper(init_curses)
    if result == "start":
        target = input("Enter the target IP or hostname: ").strip()
        min_delay = float(input("Enter the minimum delay between packets (in seconds): "))
        max_delay = float(input("Enter the maximum delay between packets (in seconds): "))
        packet_count = int(input("Enter the number of packets to send: "))
        thread_count = int(input("Enter the number of threads to use: "))

        try:
            # Resolve domain to IP if necessary
            target_ip = socket.gethostbyname(target)
            print(f"Resolved {target} to {target_ip}")

            # Create and start threads
            threads = []
            for _ in range(thread_count):
                thread = threading.Thread(target=thread_function, args=(target_ip, 64, 1500, min_delay, max_delay, packet_count))
                thread.start()
                threads.append(thread)

            # Wait for all threads to complete
            for thread in threads:
                thread.join()

        except socket.gaierror:
            print(f"Failed to resolve {target}. Please check the hostname.")
    else:
        print("Exiting program.")

def init_curses(screen):
    curses.start_color()
    curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_WHITE)

    return curses_menu(screen)

if __name__ == "__main__":
    main()
