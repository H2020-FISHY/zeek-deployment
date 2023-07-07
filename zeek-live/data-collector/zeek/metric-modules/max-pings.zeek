@load base/frameworks/sumstats
@load base/frameworks/notice
@load base/utils/exec


module METRIC_TRACK;

export {
    redef enum Notice::Type += {
        Too_Many_Icmp_Requests
    };
    const icmp_request_epoch_interval = 60secs &redef;
    const icmp_request_limit: double = 10 &redef;
}


event zeek_init()
{
    SumStats::create([$name = "metric.icmp.request.count",
            $reducers = set(SumStats::Reducer($stream="metric.icmp.request", $apply=set(SumStats::SUM))),
            $epoch = icmp_request_epoch_interval,
            $threshold_val(key: SumStats::Key, result: SumStats::Result) =
            {
            return result["metric.icmp.request"]$sum;
            },
            $threshold=icmp_request_limit,
            $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local r = result["metric.icmp.request"];
            NOTICE([$note=Too_Many_Icmp_Requests,
                    $msg=fmt("Number of ping requests over threshold (%d in the last %s)", r$num,icmp_request_epoch_interval),
                    $identifier="metric.icmp.request.count"]);
            }
    ]);
}

event icmp_echo_request(c: connection, info: icmp_info, id: count, seq: count, payload: string)
{
    SumStats::observe("metric.icmp.request", SumStats::Key(), SumStats::Observation($num=1));
}

