import os
from datetime import datetime, timedelta
from collections import defaultdict

class TimelineAggregator:
    def __init__(self):
        self.events = []
        self.timeline = []
    
    def add_events(self, events, event_type):
        for event in events:
            if isinstance(event, dict):
                event_copy = event.copy()
                event_copy['event_type'] = event_type
                if 'modify_time' in event:
                    event_copy['timestamp'] = event['modify_time']
                elif 'last_visit_time' in event:
                    event_copy['timestamp'] = event['last_visit_time']
                elif 'first_insert_time' in event:
                    event_copy['timestamp'] = event['first_insert_time']
                elif 'last_insert_time' in event:
                    event_copy['timestamp'] = event['last_insert_time']
                else:
                    event_copy['timestamp'] = datetime.now()
                self.events.append(event_copy)
    
    def build_timeline(self):
        self.timeline = sorted(self.events, key=lambda x: x['timestamp'] if x['timestamp'] else datetime.min)
        return self.timeline
    
    def detect_abnormal_periods(self, threshold=50, window_hours=24):
        abnormal_periods = []
        
        if len(self.timeline) < threshold:
            return abnormal_periods
        
        events_by_hour = defaultdict(int)
        for event in self.timeline:
            if event['timestamp']:
                hour_key = event['timestamp'].replace(minute=0, second=0, microsecond=0)
                events_by_hour[hour_key] += 1
        
        sorted_hours = sorted(events_by_hour.keys())
        for i in range(len(sorted_hours) - window_hours + 1):
            window_start = sorted_hours[i]
            window_end = window_start + timedelta(hours=window_hours)
            
            total_events = 0
            for hour in sorted_hours[i:i+window_hours]:
                total_events += events_by_hour[hour]
            
            if total_events > threshold:
                abnormal_periods.append({
                    'start_time': window_start,
                    'end_time': window_end,
                    'event_count': total_events,
                    'description': f"在 {window_start} 到 {window_end} 期间发生 {total_events} 次操作，超过阈值 {threshold}"
                })
        
        return abnormal_periods
    
    def get_events_by_type(self):
        events_by_type = defaultdict(list)
        for event in self.timeline:
            events_by_type[event['event_type']].append(event)
        return events_by_type
    
    def get_events_by_time_range(self, start_time, end_time):
        filtered = []
        for event in self.timeline:
            if event['timestamp'] and start_time <= event['timestamp'] <= end_time:
                filtered.append(event)
        return filtered
    
    def get_summary(self):
        events_by_type = self.get_events_by_type()
        return {
            'total_events': len(self.timeline),
            'events_by_type': {k: len(v) for k, v in events_by_type.items()},
            'time_range': {
                'start': self.timeline[0]['timestamp'] if self.timeline else None,
                'end': self.timeline[-1]['timestamp'] if self.timeline else None
            },
            'abnormal_periods': self.detect_abnormal_periods()
        }