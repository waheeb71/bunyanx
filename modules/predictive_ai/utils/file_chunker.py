import json
import os

class FileChunker:
    """
    Handles chunking of output files to prevent massive single-file outputs.
    """
    def __init__(self, output_dir, prefix, max_lines_per_chunk=1000000):
        self.output_dir = output_dir
        self.prefix = prefix
        self.max_lines_per_chunk = max_lines_per_chunk
        
        self.current_chunk = 1
        self.lines_written_to_current = 0
        self.current_file = None
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        self._open_new_chunk()
        
    def _get_filename(self, chunk_num):
        return os.path.join(self.output_dir, f"{self.prefix}_part_{chunk_num:04d}.jsonl")
        
    def _open_new_chunk(self):
        if self.current_file:
            self.current_file.close()
            
        path = self._get_filename(self.current_chunk)
        self.current_file = open(path, 'a', encoding='utf-8')
        self.lines_written_to_current = 0
        
    def write_record(self, record_dict):
        if self.lines_written_to_current >= self.max_lines_per_chunk:
            self.current_chunk += 1
            self._open_new_chunk()
            
        self.current_file.write(json.dumps(record_dict) + '\n')
        self.lines_written_to_current += 1
        
    def close(self):
        if self.current_file:
            self.current_file.close()
