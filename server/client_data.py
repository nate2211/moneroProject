
class ClientData:

    def __init__(self, logger):
        self.client_hashrates = {}
        self.client_newjobs = {}
        self.client_threads = {}
        self.client_last_seen = {}
        self.client_temps = {}
        self.client_status = {}
        self.client_cpu_shares = {}
        self.client_nvidia_shares = {}
        self.client_gpu_stats = {}
        self.client_power_draws = {}
        self.client_start_times = {}
        self.client_costs = {}
        self.client_pl1_pl2s = {}