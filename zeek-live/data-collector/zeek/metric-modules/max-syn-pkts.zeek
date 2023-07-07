@load base/protocols/conn
@load base/frameworks/sumstats
@load base/frameworks/notice

module METRIC_TRACK;

export {
	redef enum Notice::Type += {
		Metric_SYN_pkts_threshold_crossed
	};
	const metric_SYN_pkts_epoch_interval = 1sec &redef;
	const metric_SYN_pkts_limit: double = 500 &redef;
}

event zeek_init()
{
	SumStats::create([$name = "metric.syn.pkts.sum",
		$reducers = set(SumStats::Reducer($stream="metric.syn.pkts", $apply=set(SumStats::SUM))),
		$epoch = metric_SYN_pkts_epoch_interval,
		$threshold_val(key: SumStats::Key, result: SumStats::Result) =
		{
		return result["metric.syn.pkts"]$sum;
		},
		$threshold=metric_SYN_pkts_limit,
		$threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
		{
		local r = result["metric.syn.pkts"];
		NOTICE([$note=Metric_SYN_pkts_threshold_crossed,
			$msg=fmt("Threshold of %s crossed (%d in the last %s)", "SYN packets", r$num, metric_SYN_pkts_epoch_interval),
			$identifier="metric.syn.pkts.sum"]);
		}
	]);
}

event connection_SYN_packet(c: connection, pkt: SYN_packet)
{
	SumStats::observe("metric.syn.pkts", SumStats::Key(), SumStats::Observation($num=1));
}
