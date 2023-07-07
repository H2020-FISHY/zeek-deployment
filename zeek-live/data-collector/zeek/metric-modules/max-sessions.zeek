@load base/protocols/conn
@load base/frameworks/sumstats
@load base/frameworks/notice

module METRIC_TRACK;

export {
	redef enum Notice::Type += {
		Metric_sessions_threshold_crossed
	};
	const metric_sessions_epoch_interval = 5mins &redef;
	const metric_sessions_limit: double = 6500 &redef;
}

event zeek_init()
{
	SumStats::create([$name = "metric.conn.sessions.sum",
		$reducers = set(SumStats::Reducer($stream="metric.conn.sessions", $apply=set(SumStats::SUM))),
		$epoch = metric_sessions_epoch_interval,
		$threshold_val(key: SumStats::Key, result: SumStats::Result) =
		{
		return result["metric.conn.sessions"]$sum;
		},
		$threshold=metric_sessions_limit,
		$threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
		{
		local r = result["metric.conn.sessions"];
		NOTICE([$note=Metric_sessions_threshold_crossed,
			$msg=fmt("Threshold of %s crossed (%d in the last %s)", "sessions", r$num, metric_sessions_epoch_interval),
			$identifier="metric.conn.sessions.sum"]);
		}
	]);
}

event Conn::log_conn(rec: Conn::Info)
{
	SumStats::observe("metric.conn.sessions", SumStats::Key(), SumStats::Observation($num=1));
}
