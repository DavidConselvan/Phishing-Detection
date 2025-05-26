import { PieChart, Pie, Cell, BarChart, XAxis, YAxis, Tooltip, Bar, ResponsiveContainer } from 'recharts';
import type { PhishingCheckResult } from '../types/Phishing';

const COLORS = ['#34d399', '#ef4444'];

export const AnalysisCharts: React.FC<{ history: PhishingCheckResult[] }> = ({ history }) => {
  const total = history.length;
  const suspicious = history.filter(e => e.isPhishing).length;
  const safe = total - suspicious;

  const pieData = [
    { name: 'Suspicious', value: suspicious },
    { name: 'Safe', value: safe }
  ];

  // Aggregate reasons
  const reasonCount: Record<string, number> = {};
  history.forEach(entry => {
    entry.reasons.forEach(r => {
      reasonCount[r] = (reasonCount[r] || 0) + 1;
    });
  });

  const barData = Object.entries(reasonCount).map(([reason, count]) => ({
    reason,
    count
  }));

  return (
    <div className="grid md:grid-cols-2 gap-6 mt-4">
      <div>
        <h2 className="text-lg font-semibold mb-2">Phishing Status Distribution</h2>
        <ResponsiveContainer width="100%" height={250}>
          <PieChart>
            <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label>
              {pieData.map((entry, index) => (
                <Cell key={index} fill={COLORS[index % COLORS.length]} />
              ))}
            </Pie>
            <Tooltip />
          </PieChart>
        </ResponsiveContainer>
      </div>

      <div>
        <h2 className="text-lg font-semibold mb-2">Suspicion Reason Frequency</h2>
        <ResponsiveContainer width="100%" height={300}>
          <BarChart data={barData}>
            <XAxis dataKey="reason" tick={{ fontSize: 10 }} interval={0} angle={-30} textAnchor="end" />
            <YAxis />
            <Tooltip />
            <Bar dataKey="count" fill="#60a5fa" />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};
