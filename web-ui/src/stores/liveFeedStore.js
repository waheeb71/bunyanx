import { create } from 'zustand';

const MAX_LOGS = 100;

export const useLiveFeedStore = create((set, get) => ({
  // WAF Live Feed
  wafEvents: [],
  wafBlocked: 0,
  wafChallenged: 0,

  // Live Monitor (Dashboard)
  wsState: 'closed',
  trafficHistory: [],
  alertsFeed: [],
  liveStats: null,

  setWsState: (wsState) => set({ wsState }),

  addWafEvent: (ev) => {
    set(state => {
      const isBlock = ev.action === 'BLOCK';
      const isChallenge = ev.action === 'CHALLENGE' || ev.action === 'QUARANTINE';
      return {
        wafEvents: [ev, ...state.wafEvents].slice(0, MAX_LOGS),
        wafBlocked: isBlock ? state.wafBlocked + 1 : state.wafBlocked,
        wafChallenged: isChallenge ? state.wafChallenged + 1 : state.wafChallenged,
      };
    });
  },

  setWafInitialStats: (blocked, challenged) => {
    set({ wafBlocked: blocked, wafChallenged: challenged });
  },

  setLiveStats: (stats) => {
    set({ liveStats: stats });
  },

  // Live Monitor Actions
  addTrafficLog: (log) => {
    set(state => ({
      trafficHistory: [...state.trafficHistory, log].slice(-MAX_LOGS)
    }));
  },

  addAlertLog: (alert) => {
    set(state => ({
      alertsFeed: [alert, ...state.alertsFeed].slice(0, MAX_LOGS)
    }));
  },

  clearAll: () => set({ wafEvents: [], trafficHistory: [], alertsFeed: [], liveStats: null }),
}));

export default useLiveFeedStore;
