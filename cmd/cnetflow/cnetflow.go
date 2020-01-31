package main

import (
	"bytes"
	"fmt"
	//"github.com/BekzhanKaspakov/friendly-giggle/utils"
	"github.com/cloudflare/goflow/utils"
	"github.com/cloudflare/goflow/decoders/netflow"
	flowmessage "github.com/cloudflare/goflow/pb"
	"github.com/cloudflare/goflow/producer"
	"github.com/prometheus/client_golang/prometheus"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)



func main() {
	templates := make(map[string]*utils.TemplateSystem)
	count := 1
	if handle, err := pcap.OpenOffline("netflow-template.pcap"); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			fmt.Printf("packet #%d\n", count)
			count++
			if packet.NetworkLayer() != nil {
				handlePacket(packet, templates)
			}

		}
	}
	if handle, err := pcap.OpenOffline("netflow1.pcap"); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			fmt.Printf("packet #%d\n", count)
			count++
			if packet.NetworkLayer() != nil {
				handlePacket(packet, templates)
			}
		}
	}
}


func handlePacket(packet gopacket.Packet, templates map[string]*utils.TemplateSystem) {
	packet.ApplicationLayer().Payload()
	buf := bytes.NewBuffer(packet.ApplicationLayer().Payload())

	key := packet.NetworkLayer().NetworkFlow().Dst().String()
	samplerAddress := net.ParseIP(key)
	if samplerAddress.To4() != nil {
		samplerAddress = samplerAddress.To4()
	}

	templatess, ok := templates[key]

	if !ok {
		templatess = &utils.TemplateSystem{
			Templates: netflow.CreateTemplateSystem(),
			Key:       key,
		}
		templates[key] = templatess
	}
	//timeTrackStart := time.Now()
	msgDec, err := netflow.DecodeMessage(buf, templatess)
	if err != nil {
		switch err.(type) {
		case *netflow.ErrorVersion:
			utils.NetFlowErrors.With(
				prometheus.Labels{
					"router": key,
					"error":  "error_version",
				}).
				Inc()
		case *netflow.ErrorFlowId:
			utils.NetFlowErrors.With(
				prometheus.Labels{
					"router": key,
					"error":  "error_flow_id",
				}).
				Inc()
		case *netflow.ErrorTemplateNotFound:
			utils.NetFlowErrors.With(
				prometheus.Labels{
					"router": key,
					"error":  "template_not_found",
				}).
				Inc()
		default:
			utils.NetFlowErrors.With(
				prometheus.Labels{
					"router": key,
					"error":  "error_decoding",
				}).
				Inc()
		}
		fmt.Println(err)
		return
	}

	flowMessageSet := make([]*flowmessage.FlowMessage, 0)

	switch msgDecConv := msgDec.(type) {
	case netflow.NFv9Packet:
		utils.NetFlowStats.With(
			prometheus.Labels{
				"router":  key,
				"version": "9",
			}).
			Inc()

		for _, fs := range msgDecConv.FlowSets {
			switch fsConv := fs.(type) {
			case netflow.TemplateFlowSet:
				utils.NetFlowSetStatsSum.With(
					prometheus.Labels{
						"router":  key,
						"version": "9",
						"type":    "TemplateFlowSet",
					}).
					Inc()

				utils.NetFlowSetRecordsStatsSum.With(
					prometheus.Labels{
						"router":  key,
						"version": "9",
						"type":    "OptionsTemplateFlowSet",
					}).
					Add(float64(len(fsConv.Records)))

			case netflow.NFv9OptionsTemplateFlowSet:
				utils.NetFlowSetStatsSum.With(
					prometheus.Labels{
						"router":  key,
						"version": "9",
						"type":    "OptionsTemplateFlowSet",
					}).
					Inc()

				utils.NetFlowSetRecordsStatsSum.With(
					prometheus.Labels{
						"router":  key,
						"version": "9",
						"type":    "OptionsTemplateFlowSet",
					}).
					Add(float64(len(fsConv.Records)))

			case netflow.OptionsDataFlowSet:
				utils.NetFlowSetStatsSum.With(
					prometheus.Labels{
						"router":  key,
						"version": "9",
						"type":    "OptionsDataFlowSet",
					}).
					Inc()

				utils.NetFlowSetRecordsStatsSum.With(
					prometheus.Labels{
						"router":  key,
						"version": "9",
						"type":    "OptionsDataFlowSet",
					}).
					Add(float64(len(fsConv.Records)))
			case netflow.DataFlowSet:
				utils.NetFlowSetStatsSum.With(
					prometheus.Labels{
						"router":  key,
						"version": "9",
						"type":    "DataFlowSet",
					}).
					Inc()

				utils.NetFlowSetRecordsStatsSum.With(
					prometheus.Labels{
						"router":  key,
						"version": "9",
						"type":    "DataFlowSet",
					}).
					Add(float64(len(fsConv.Records)))
			}
		}
		flowMessageSet, err = producer.ProcessMessageNetFlow(msgDecConv, nil)

		for _, fmsg := range flowMessageSet {
			fmt.Print("NFv9:")
			fmt.Println(fmsg.String())
			//fmt.Print(fmsg.SrcIP)
			//fmt.Print(", ")
			//fmt.Printf("%d \n", fmsg.DstIP)
		}
	case netflow.IPFIXPacket:
		utils.NetFlowStats.With(
			prometheus.Labels{
				"router":  key,
				"version": "10",
			}).
			Inc()

		for _, fs := range msgDecConv.FlowSets {
			switch fsConv := fs.(type) {
			case netflow.TemplateFlowSet:
				utils.NetFlowSetStatsSum.With(
					prometheus.Labels{
						"router":  key,
						"version": "10",
						"type":    "TemplateFlowSet",
					}).
					Inc()

				utils.NetFlowSetRecordsStatsSum.With(
					prometheus.Labels{
						"router":  key,
						"version": "10",
						"type":    "TemplateFlowSet",
					}).
					Add(float64(len(fsConv.Records)))

			case netflow.IPFIXOptionsTemplateFlowSet:
				utils.NetFlowSetStatsSum.With(
					prometheus.Labels{
						"router":  key,
						"version": "10",
						"type":    "OptionsTemplateFlowSet",
					}).
					Inc()

				utils.NetFlowSetRecordsStatsSum.With(
					prometheus.Labels{
						"router":  key,
						"version": "10",
						"type":    "OptionsTemplateFlowSet",
					}).
					Add(float64(len(fsConv.Records)))

			case netflow.OptionsDataFlowSet:

				utils.NetFlowSetStatsSum.With(
					prometheus.Labels{
						"router":  key,
						"version": "10",
						"type":    "OptionsDataFlowSet",
					}).
					Inc()

				utils.NetFlowSetRecordsStatsSum.With(
					prometheus.Labels{
						"router":  key,
						"version": "10",
						"type":    "OptionsDataFlowSet",
					}).
					Add(float64(len(fsConv.Records)))

			case netflow.DataFlowSet:
				utils.NetFlowSetStatsSum.With(
					prometheus.Labels{
						"router":  key,
						"version": "10",
						"type":    "DataFlowSet",
					}).
					Inc()

				utils.NetFlowSetRecordsStatsSum.With(
					prometheus.Labels{
						"router":  key,
						"version": "10",
						"type":    "DataFlowSet",
					}).
					Add(float64(len(fsConv.Records)))
			}
		}
		flowMessageSet, err = producer.ProcessMessageNetFlow(msgDecConv, nil)

		for _, fmsg := range flowMessageSet {
			fmt.Println("IPFIX:")
			fmt.Print(fmsg.SrcIP)
			fmt.Print(", ")
			fmt.Print(fmsg.DstIP)
		}
	}
}