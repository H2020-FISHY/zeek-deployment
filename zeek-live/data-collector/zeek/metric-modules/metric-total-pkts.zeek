@load base/protocols/conn
@load base/frameworks/sumstats
@load base/frameworks/notice

module METRIC_TRACK;

export {
	redef enum Notice::Type += {
		Metric_threshold_crossed_total_pkts_sum
	};
	const metric_total_pkts_epoch_interval = 1hrs &redef;
	const metric_total_pkts_limit: double = 1500000.0 &redef;
}

event zeek_init()
{
	SumStats::create([$name = "metric.conn.total_pkts.sum",
		$reducers = set(SumStats::Reducer($stream="metric.conn.total_pkts", $apply=set(SumStats::SUM))),
		$epoch = metric_total_pkts_epoch_interval,
		$threshold_val(key: SumStats::Key, result: SumStats::Result) =
		{
		return result["metric.conn.total_pkts"]$sum;
		},
		$threshold=metric_total_pkts_limit,
		$threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
		{
		local r = result["metric.conn.total_pkts"];
		NOTICE([$note=Metric_threshold_crossed_total_pkts_sum,
			$msg=fmt("Threshold of %s crossed (%f in the last %s)", "total_pkts", r$sum, metric_total_pkts_epoch_interval),
			$identifier="metric.conn.total_pkts.sum"]);
		}
	]);
}

event Conn::log_conn(rec: Conn::Info)
{
		SumStats::observe("metric.conn.total_pkts", SumStats::Key(), SumStats::Observation($dbl=|rec$orig_pkts + rec$resp_pkts|));
}
