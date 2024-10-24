use serde::Deserialize;

#[derive(Debug, Deserialize)]
/// Represents the entire chart data.
pub struct Performance {
    /// Performance Baseline represents over all portfolio performance
    pub performance_baseline: PerformanceBaseline,
}

#[derive(Debug, Deserialize)]
/// Represents the performance baseline data.
pub struct PerformanceBaseline {
    /// The currency in 3 char format
    pub currency_code: String,
    /// The currency ID
    pub currency_id: String,
    /// The amount
    pub amount: String,
}
