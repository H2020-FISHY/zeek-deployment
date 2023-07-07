@load base/protocols/conn
@load base/frameworks/sumstats
@load base/frameworks/notice

module METRIC_TRACK;

export {
	redef enum Notice::Type += {
		Metric_threshold_crossed_sessions_sum
	};
	const metric_sessions_epoch_interval = 1hrs &redef;
	const metric_sessions_limit: double = 50000.0 &redef;
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
		NOTICE([$note=Metric_threshold_crossed_sessions_sum,
			$msg=fmt("Threshold of %s crossed (%f in the last %s)", "sessions", r$sum, metric_sessions_epoch_interval),
			$identifier="metric.conn.sessions.sum"]);
		}
	]);
}

event Conn::log_conn(rec: Conn::Info)
{
	SumStats::observe("metric.conn.sessions", SumStats::Key(), SumStats::Observation($dbl=1));
}
