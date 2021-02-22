import dpkt
import geoip2.database
import socket
import pandas as pd


def ip_geo_info_(target):
    with geoip2.database.Reader('GeoLite2/GeoLite2-City.mmdb') as reader:
        resp = reader.city(target)
        city = resp.city.name
        region = resp.subdivisions.most_specific.name
        iso = resp.country.iso_code
        lat = resp.location.latitude
        long = resp.location.longitude
        data = [city, region, iso, lat, long]
        for i in range(len(data)):
            if data[i] is None:
                data[i] = "Unknown"
        return data


def print_pcap(pcap):
    for ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            desc = "[+] Src: {} --> Dst: {} ".format(src, dst)
            print(desc)
        except:
            pass


f = open('pcaps/2020-08-21-traffic-analysis-exercise.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)
print_pcap(pcap)
print(ip_geo_info_('8.8.8.8'))
