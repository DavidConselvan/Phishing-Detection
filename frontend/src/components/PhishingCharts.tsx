import { PieChart, Pie, Cell, BarChart, XAxis, YAxis, Tooltip, Bar, ResponsiveContainer } from 'recharts';
import type { PhishingCheckResult } from '../types/Phishing';

const PIE_BLUE = '#60a5fa'; // Tailwind blue-400, matches 'Safe' text
const PIE_RED = '#ef4444';  // Tailwind red-500, matches 'Suspicious' text
const COLORS = [PIE_RED, PIE_BLUE]; // Suspicious: red, Safe: blue

const ML_COLORS: Record<string, string> = {
  benign: PIE_BLUE,
  safe: PIE_BLUE,
  phishing: PIE_RED,
  suspicious: PIE_RED,
  unknown: '#f59e42', // orange-400
};
const ML_BAR_COLOR = PIE_BLUE;

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

  // ML Model label distribution and average score
  const mlLabelCount: Record<string, number> = {};
  const mlLabelScoreSum: Record<string, number> = {};
  const mlLabelScoreCount: Record<string, number> = {};

  history.forEach(entry => {
    if (entry.ml_model && entry.ml_model.label) {
      const label = entry.ml_model.label;
      mlLabelCount[label] = (mlLabelCount[label] || 0) + 1;
      mlLabelScoreSum[label] = (mlLabelScoreSum[label] || 0) + (entry.ml_model.score || 0);
      mlLabelScoreCount[label] = (mlLabelScoreCount[label] || 0) + 1;
    }
  });

  const mlPieData = Object.entries(mlLabelCount).map(([label, value]) => ({
    name: label,
    value
  }));

  const mlBarData = Object.entries(mlLabelScoreSum).map(([label, sum]) => ({
    label,
    avgScore: mlLabelScoreCount[label] ? (sum / mlLabelScoreCount[label]) : 0
  }));

  return (
    <>
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
              <XAxis dataKey="reason" tick={{ fontSize: 10, fill: '#cbd5e1' }} interval={0} angle={-30} textAnchor="end" />
              <YAxis tick={{ fill: '#cbd5e1' }} />
              <Tooltip contentStyle={{ backgroundColor: '#23283a', border: '1px solid #334155', color: '#e5e7eb' }} />
              <Bar dataKey="count" fill={PIE_BLUE} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
      {/* ML Model Statistics */}
      <div className="grid md:grid-cols-2 gap-6 mt-4">
        <div>
          <h2 className="text-lg font-semibold mb-2">ML Model Label Distribution</h2>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie
                data={mlPieData}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                outerRadius={80}
                label
              >
                {mlPieData.map((entry, index) => (
                  <Cell
                    key={index}
                    fill={ML_COLORS[entry.name] || '#64748b'}
                  />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
        <div>
          <h2 className="text-lg font-semibold mb-2">Average ML Model Score by Label</h2>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={mlBarData}>
              <XAxis dataKey="label" tick={{ fill: '#cbd5e1' }} />
              <YAxis tick={{ fill: '#cbd5e1' }} />
              <Tooltip contentStyle={{ backgroundColor: '#23283a', border: '1px solid #334155', color: '#e5e7eb' }} />
              <Bar dataKey="avgScore" fill={ML_BAR_COLOR} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </>
  );
};
