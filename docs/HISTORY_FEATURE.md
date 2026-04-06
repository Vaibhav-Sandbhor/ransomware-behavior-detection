# Historical Data Viewer Feature

Comprehensive guide for the new History feature in CyberSIEM.

## 📋 Overview

The Historical Data Viewer allows users to:
- Browse past scan dates
- View historical scan metrics (threat counts over time)
- Review past threat events with severity classification
- Compare historical data with current real-time data

## 🎯 User Flow

1. **Click "📅 History"** in the sidebar
2. **System loads available dates** from the database
3. **Select a date** from the list
4. **Dashboard updates** with metrics and events from that date
5. **Review historical data** with summary statistics
6. **Click "Back to Live"** to return to real-time monitoring

## 🔌 Backend API Endpoints

### GET /history/dates
Returns list of available dates with historical data.

**Query Parameters:** None

**Response:**
```json
{
  "dates": [
    "2026-04-06",
    "2026-04-05",
    "2026-04-04"
  ],
  "total": 3
}
```

**Status Codes:**
- 200: Success
- 401: Unauthorized (JWT required)
- 500: Database error

---

### GET /history/metrics?date=YYYY-MM-DD
Returns all metrics (threat counts) for a specific date.

**Query Parameters:**
- `date` (required): Date in format `YYYY-MM-DD`

**Response:**
```json
{
  "date": "2026-04-06",
  "metrics": [
    {
      "id": 1,
      "timestamp": "2026-04-06 10:30:45",
      "ransomware_count": 5,
      "portscan_count": 2,
      "honeypot_hits": 1
    },
    {
      "id": 2,
      "timestamp": "2026-04-06 11:00:15",
      "ransomware_count": 5,
      "portscan_count": 2,
      "honeypot_hits": 2
    }
  ],
  "summary": {
    "max_ransomware": 5,
    "max_portscan": 2,
    "max_honeypot": 2,
    "first_recorded": "2026-04-06 10:30:45",
    "last_recorded": "2026-04-06 15:45:30"
  },
  "total": 45
}
```

**Status Codes:**
- 200: Success
- 401: Unauthorized
- 500: Database error

---

### GET /history/events?date=YYYY-MM-DD
Returns all threat events for a specific date.

**Query Parameters:**
- `date` (required): Date in format `YYYY-MM-DD`

**Response:**
```json
{
  "date": "2026-04-06",
  "events": [
    {
      "id": 1,
      "module": "ransomware",
      "event_type": "encryption_activity",
      "severity": "CRITICAL",
      "details": "Detected 5 ransomware threat(s)",
      "timestamp": "2026-04-06 10:30:45"
    },
    {
      "id": 2,
      "module": "portscan",
      "event_type": "port_detected",
      "severity": "HIGH",
      "details": "Port 22 is open (Risk: HIGH)",
      "timestamp": "2026-04-06 10:31:00"
    }
  ],
  "severity_counts": {
    "CRITICAL": 5,
    "HIGH": 8,
    "MEDIUM": 3,
    "LOW": 2
  },
  "total": 18
}
```

**Status Codes:**
- 200: Success
- 401: Unauthorized
- 500: Database error

---

### GET /health/history
Health check endpoint to verify historical data availability.

**Response (Database Available):**
```json
{
  "status": "available",
  "metrics_entries": 1250,
  "event_entries": 350,
  "database": "cybersiem_data.db"
}
```

**Response (Database Disabled):**
```json
{
  "status": "disabled",
  "message": "Database not available"
}
```

## 🎨 Frontend Components

### HistoryViewer.jsx
Main component for historical data viewing.

**Features:**
- Date selector with list of available dates
- Auto-loads most recent date on mount
- Displays metrics summary (max threat counts)
- Shows severity-classified events
- Time range display (first to last recorded)
- Error handling with user-friendly messages
- Back to Live button for quick return to dashboard

**Props:**
- `onSelectDate` (optional): Callback function when date is selected

**Usage:**
```jsx
import HistoryViewer from "./pages/HistoryViewer.jsx";

<HistoryViewer onSelectDate={(date, metrics, events) => {
  // Update dashboard with historical data
}} />
```

### Sidebar Integration
Added "📅 History" menu item to sidebar with visual separator.

**Styling:**
- Gradient background (blue accent)
- Border highlight on hover
- Visual divider line above entry

## 🔄 State Management

The history feature integrates with existing state without modifications:

- **moduleData**: Populated with latest values from selected date
- **timelineData**: Contains metrics timeline for charts
- **alerts**: Contains threat events as alerts

### Future Enhancement: Mode Switching
For live/history mode switching:

```javascript
const [mode, setMode] = useState("live"); // "live" or "history"

// In history mode:
// - Stop auto-polling
// - Display "Viewing history for YYYY-MM-DD" label
// - Show "Back to Live" button

// In live mode:
// - Resume auto-polling
// - Update moduleData in real-time
```

## 📊 Data Flow

```
User Click: "History"
    ↓
Load /history/dates
    ↓
Display date list
    ↓
User selects date
    ↓
Fetch /history/metrics?date=YYYY-MM-DD
Fetch /history/events?date=YYYY-MM-DD
    ↓
Display:
  - Metrics Summary (Max threat counts)
  - Threat Events (Severity breakdown)
  - Time range (First to last record)
    ↓
User clicks "Back to Live"
    ↓
Return to Dashboard (live mode)
```

## 🔐 Security

- **Authentication Required**: All endpoints require JWT Bearer token
- **Query Parameters Validated**: Date format validated server-side
- **Error Messages Generic**: No sensitive information leaked
- **Database Queries Parameterized**: SQL injection prevented
- **User Isolation**: (Future) Filter events by user/session

## 📈 Performance

- **Indexed Queries**: Responses typically <100ms
- **Limited Results**: Events limited to 100 per query
- **Date Filtering**: Only loads data for selected date
- **Lazy Loading**: Data loaded only when date selected

## 🧪 Testing Checklist

**Backend:**
- [ ] Get /history/dates returns all dates (sorted DESC)
- [ ] Get /history/metrics returns metrics for date with summary
- [ ] Get /history/events returns events for date with counts
- [ ] All endpoints require JWT authentication
- [ ] Invalid date format returns error
- [ ] Database unavailable returns appropriate error

**Frontend:**
- [ ] History menu item visible in sidebar
- [ ] Clicking History navigates to /history
- [ ] Available dates load on component mount
- [ ] Most recent date auto-selected
- [ ] Date selection loads metrics and events
- [ ] Metrics summary displays correctly
- [ ] Events list shows severity breakdown
- [ ] Back to Live button returns to dashboard
- [ ] Error messages display on network errors

**Integration:**
- [ ] Real-time data continues while viewing history
- [ ] Authority to create new scans while in history mode
- [ ] Switching back to live resumes auto-polling

## 🚀 Deployment Notes

1. **Database Required**: Ensure SQLite database initialized
2. **Migration**: Existing scan data will appear in history automatically
3. **Retention**: Consider cleanup policy for old data (optional future feature)
4. **Backup**: Database file (`cybersiem_data.db`) should be included in backups

## 🔮 Future Enhancements

1. **Live/History Mode Switching**: Pause real-time when viewing history
2. **Date Range Selection**: Compare data across multiple dates
3. **Export Functionality**: Download historical data as CSV/PDF
4. **Retention Policy**: Auto-cleanup of data older than N days
5. **Search Events**: Filter events by severity, module, or keyword
6. **Trend Analysis**: Show threat trends over multiple days
7. **Annotations**: Allow users to add notes to historical events
8. **Compliance Reports**: Generate security reports for historical periods

## 📝 API Examples

### Using curl

```bash
# Get available dates
curl -H "Authorization: Bearer TOKEN" \
  http://localhost:8000/history/dates

# Get metrics for a date
curl -H "Authorization: Bearer TOKEN" \
  "http://localhost:8000/history/metrics?date=2026-04-06"

# Get events for a date
curl -H "Authorization: Bearer TOKEN" \
  "http://localhost:8000/history/events?date=2026-04-06"
```

### Using JavaScript

```javascript
// Get dates
const dates = await fetch('/history/dates', {
  headers: { 'Authorization': `Bearer ${token}` }
}).then(r => r.json());

// Get metrics
const metrics = await fetch(
  `/history/metrics?date=${date}`,
  { headers: { 'Authorization': `Bearer ${token}` } }
).then(r => r.json());

// Get events
const events = await fetch(
  `/history/events?date=${date}`,
  { headers: { 'Authorization': `Bearer ${token}` } }
).then(r => r.json());
```

## 🆘 Troubleshooting

**No dates appear**
- Check database initialization
- Verify scan data exists in database
- Check /health/history endpoint

**404 errors on endpoints**
- Verify api_server.py restarted
- Check Flask/FastAPI routing
- Verify database module imported

**Unauthorized errors**
- JWT token may have expired
- Check Authorization header format
- Verify token still valid

**Slow response times**
- Check database indexes
- Monitor system resources
- Consider limiting date range

## 📞 Support

For issues or questions:
1. Check database health: `GET /health/history`
2. Verify JWT token validity
3. Review server logs for errors
4. Ensure database file exists and is readable
