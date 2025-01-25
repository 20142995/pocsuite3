# Dionaea 的Memcached协议举例，在实现Memcached协议时Dionaea在一些参数如：version、libevent和rusage_user等都是固定的。
# 仅需IP和端口
import memcache
from pocsuite3.api import Output, POCBase, register_poc


class MemcacheHoneypot(POCBase):
    vulID = '0011'  # ssvid
    author = ['jstang']
    name = "Dionaea Memcache 蜜罐服务"
    project = 'Dionaea'
    appName = 'Memcache'
    appVersion = 'None'
    desc = "Dionaea Memcached协议举例,在实现Memcached协议时Dionaea把很多参数做了随机化,但是在一些参数如: version,libevent和rusage_user等都是固定的."

    def _attack(self):
        print(">>>>execute _attack")
        return self._verify()

    def _verify(self):
        try:
            attr = self.target.split(':')
            if attr[1] != '11211':
                return self.parse_output({})

            array = []
            mc = memcache.Client([self.target])
            stats = mc.get_stats()

            data = stats[0]
            data = data[1]
            if data['version'] == '1.6.9': 
                array.append("Non randomized features: version=1.4.25")
            if data['libevent'] == '2.0.22-stable':
                array.append("Non randomized features: libevent=2.0.22-stable")
            if data['rusage_system'] == "0.233":
                array.append("Non randomized features: rusage_system=0.233")
            if data['rusage_user'] == "0.550000":
                array.append("Non randomized features: rusage_user=0.550000")

            if not array:
                return self.parse_output({})
            return self.parse_output({'verify': ','.join(array)})
        except Exception as e:
            print(e)
            return self.parse_output({})

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(MemcacheHoneypot)

'''
[
    (
        '172.31.50.249:11211 (1)',
        {
            'pid': '1', 'uptime': '231', 'time': '1612091156', 'version': '1.6.9',
            'libevent': '2.1.8-stable', 'pointer_size': '64', 'rusage_user': '0.058336',
            'rusage_system': '0.019894', 'max_connections': '1024', 'curr_connections': '2',
            'total_connections': '7', 'rejected_connections': '0', 'connection_structures': '3',
            'response_obj_oom': '0', 'response_obj_count': '1', 'response_obj_bytes': '65536',
            'read_buf_count': '8', 'read_buf_bytes': '131072', 'read_buf_bytes_free': '49152',
            'read_buf_oom': '0', 'reserved_fds': '20', 'cmd_get': '0', 'cmd_set': '0',
            'cmd_flush': '0', 'cmd_touch': '0', 'cmd_meta': '0', 'get_hits': '0',
            'get_misses': '0', 'get_expired': '0', 'get_flushed': '0', 'delete_misses': '0',
            'delete_hits': '0', 'incr_misses': '0', 'incr_hits': '0', 'decr_misses': '0',
            'decr_hits': '0', 'cas_misses': '0', 'cas_hits': '0', 'cas_badval': '0',
            'touch_hits': '0', 'touch_misses': '0', 'auth_cmds': '0', 'auth_errors': '0',
            'bytes_read': '35', 'bytes_written': '8553', 'limit_maxbytes': '67108864',
            'accepting_conns': '1', 'listen_disabled_num': '0',
            'time_in_listen_disabled_us': '0', 'threads': '4', 'conn_yields': '0',
            'hash_power_level': '16', 'hash_bytes': '524288', 'hash_is_expanding': '0',
            'slab_reassign_rescues': '0', 'slab_reassign_chunk_rescues': '0',
            'slab_reassign_evictions_nomem': '0', 'slab_reassign_inline_reclaim': '0',
            'slab_reassign_busy_items': '0', 'slab_reassign_busy_deletes': '0',
            'slab_reassign_running': '0', 'slabs_moved': '0', 'lru_crawler_running': '0',
            'lru_crawler_starts': '3', 'lru_maintainer_juggles': '281', 'malloc_fails': '0',
            'log_worker_dropped': '0', 'log_worker_written': '0', 'log_watcher_skipped': '0',
            'log_watcher_sent': '0', 'unexpected_napi_ids': '0', 'round_robin_fallback': '0',
            'bytes': '0', 'curr_items': '0', 'total_items': '0', 'slab_global_page_pool': '0',
            'expired_unfetched': '0', 'evicted_unfetched': '0', 'evicted_active': '0',
            'evictions': '0', 'reclaimed': '0', 'crawler_reclaimed': '0',
            'crawler_items_checked': '0', 'lrutail_reflocked': '0', 'moves_to_cold': '0',
            'moves_to_warm': '0', 'moves_within_lru': '0', 'direct_reclaims': '0',
            'lru_bumps_dropped': '0'
        }
    )
]
'''
