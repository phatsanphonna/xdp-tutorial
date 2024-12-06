#include <linux/in.h>
#include <linux/if_ether.h>
#include <stdio.h>

void mac_address_to_string(const __u8 *address, char *buffer)
{
    snprintf(buffer, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             address[0], address[1], address[2],
             address[3], address[4], address[5]);
}
