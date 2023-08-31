def remove_ether_header(packet):
    if Ether in packet:
        return packet[Ether].payload 

    return packet  


def mask_ip(packet):  
    if IP in packet:  
        packet[IP].src = '0.0.0.0'  
        packet[IP].dst = '0.0.0.0'  

    return packet


def pad_udp(packet):
    if UDP in packet:
        # get layers after udp
        layer_after = packet[UDP].payload.copy()

        # build a padding layer
        pad = Padding()
        pad.load = '\x00' * 12

        layer_before = packet.copy()
        layer_before[UDP].remove_payload()
        packet = layer_before / pad / layer_after

        return packet  

    return packet  
    
    
def should_omit_packet(packet):  
    # SYN, ACK or FIN flags set to 1 and no payload 
    if TCP in packet and (packet.flags & 0x13):
        # not payload or contains only padding
        layers = packet[TCP].payload.layers()  
        if not layers or (Padding in layers and len(layers) == 1):  
            return True

    # DNS segment
    if DNS in packet:  
        return True 

    return False