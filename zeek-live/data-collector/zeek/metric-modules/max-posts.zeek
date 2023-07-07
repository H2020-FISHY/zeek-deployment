@load base/protocols/http
@load base/frameworks/sumstats
@load base/frameworks/notice

module METRIC_TRACK;

export {
	redef enum Notice::Type += {
		Metric_http_posts_threshold_crossed
	};
	const metric_http_posts_epoch_interval = 1mins &redef;
	const metric_http_posts_limit: double = 1 &redef;
}

event zeek_init()
{
	SumStats::create([$name = "metric.http.posts.sum",
		$reducers = set(SumStats::Reducer($stream="metric.http.posts", $apply=set(SumStats::SUM))),
		$epoch = metric_http_posts_epoch_interval,
		$threshold_val(key: SumStats::Key, result: SumStats::Result) =
		{
		return result["metric.http.posts"]$sum;
		},
		$threshold=metric_http_posts_limit,
		$threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
		{
		local r = result["metric.http.posts"];
		NOTICE([$note=Metric_http_posts_threshold_crossed,
			$msg=fmt("Threshold of %s crossed (%d in the last %s)", "http posts", r$num, metric_http_posts_epoch_interval),
			$identifier="metric.http.posts.sum"]);
		}
	]);
}

event HTTP::log_http(rec: HTTP::Info)
{
    if(rec?$method && rec$method == "POST") 
        SumStats::observe("metric.http.posts", SumStats::Key(), SumStats::Observation($num=1));
}
