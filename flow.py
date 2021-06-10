
class flow():
  def  __init__(self, src, dst, src_port,dst_port, proto, start, total_bytes):
    self.src = src
    self.dst = dst
    self.src_port = src_port
    self.dst_port = dst_port
    self.proto = proto
    self.dir = ''
    self.start = start
    self.dur = '0.0000'
    self.tot_packets = 1
    self.tot_bytes = total_bytes
    self.src_bytes = 0
    self.fin = False
    self.last_seen = start

  def source_bytes(self, bytes):
    self.src_bytes += bytes
  
  def total_bytes(self, bytes):
    self.tot_bytes += bytes
  
  def total_packets(self):
    self.tot_packets += 1

  def duration(self, cur_time):
    self.dur = str(cur_time - self.start)

  def direction_forward(self):
    if '>' not in self.dir:
      self.dir += '>'

  def direction_backward(self):
    if '<' not in self.dir:
      self.dir = '<' + self.dir
      
  def print_flow(self):
    return f"{self.start},{self.dur},{self.proto},{self.src},{self.dir},{self.dst},{self.tot_packets},{self.tot_bytes},{self.src_bytes}\n"
