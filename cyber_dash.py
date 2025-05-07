import pandas as pd
import requests
import plotly.express as px
from dash import Dash, dcc, html, Input, Output
import dash_bootstrap_components as dbc
from collections import Counter

# --- 1. Fetch Data from HIBP API ---
url = "https://haveibeenpwned.com/api/v3/breaches"
headers = {
    "User-Agent": "DashApp - Breach Analysis"
}
response = requests.get(url, headers=headers)
data = response.json()

# --- 2. Clean and Prepare Data ---
df = pd.DataFrame(data)
df['BreachDate'] = pd.to_datetime(df['BreachDate'], errors='coerce')
df['AddedDate'] = pd.to_datetime(df['AddedDate'], errors='coerce')
df['AccountsAffected'] = df['PwnCount']
df['Description'] = df['Description'].str.replace('<[^<]+?>', '', regex=True)
df['Year'] = df['BreachDate'].dt.year
df['BreachTitle'] = df['Title']

# --- 3. Create Visualizations ---
# Breaches over time
breaches_by_year = df.groupby('Year').size().reset_index(name='Count')
fig1 = px.bar(breaches_by_year, x='Year', y='Count', title='Breaches Per Year')

# Most common data classes
all_classes = sum(df['DataClasses'], [])
class_counts = pd.DataFrame(Counter(all_classes).most_common(), columns=['DataClass', 'Count']).head(20)
fig2 = px.bar(class_counts, x='Count', y='DataClass', orientation='h', title='Most Common Compromised Data Types')

# Top 15 breaches
top_breaches = df.sort_values(by='AccountsAffected', ascending=False).head(15)
fig3 = px.bar(
    top_breaches,
    x='AccountsAffected',
    y='BreachTitle',
    orientation='h',
    title='Top 15 Breaches by Accounts Affected',
    hover_data=['BreachDate']
)

# Verified vs Unverified
verified_counts = df['IsVerified'].value_counts().rename({True: 'Verified', False: 'Unverified'}).reset_index()
verified_counts.columns = ['VerificationStatus', 'Count']
fig4 = px.pie(verified_counts, names='VerificationStatus', values='Count', title='Verified vs Unverified Breaches')

# --- 4. Dash App Layout with Tabs ---
app = Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP])

app.layout = dbc.Container([
    html.H1("Credential Breach Analysis Dashboard", className="text-center mb-4"),

    dcc.Tabs([
        dcc.Tab(label='Overview', children=[
            html.Div([
                html.H4("Dashboard Overview"),
                html.P("""
                    This dashboard provides an interactive analysis of publicly reported credential breaches 
                    using data from the Have I Been Pwned (HIBP) API. The purpose of this tool is to help users, 
                    researchers, and security professionals visualize breach trends, understand the scale and types 
                    of data compromised, and explore specific major breaches in greater detail.
                """),
                html.P("""
                    The visualizations aim to raise cybersecurity awareness by highlighting common data types 
                    exposed in breaches (like email addresses, passwords, and IP addresses), showing trends over 
                    time, and distinguishing between verified and unverified reports.
                """),
                html.P([
                    "Data Source: ",
                    html.A("Have I Been Pwned (https://haveibeenpwned.com/API/v3)", 
                        href="https://haveibeenpwned.com/API/v3", target="_blank")
                ]),
                html.P("Note: Breach data is sourced from publicly known incidents and may not represent all breaches."),
            ], style={'padding': '20px'})
        ]),

        dcc.Tab(label='Top 15 Breaches', children=[
            dcc.Graph(id='top-breaches-chart', figure=fig3),
            html.Div(id='breach-details', style={
                'whiteSpace': 'pre-wrap',
                'padding': '10px',
                'border': '1px solid #ccc'
            })
        ]),
        dcc.Tab(label='Breaches Over Time', children=[
            dcc.Graph(id='breaches-over-time-chart', figure=fig1),
            html.Div("This chart shows the number of breaches reported each year. Hover over a bar to see details."),
            dcc.Graph(id='top-breaches-year-chart'),
            html.Div(id='yearly-breach-details', style={'whiteSpace': 'pre-wrap', 'padding': '10px', 'border': '1px solid #ccc'}),

        ]),
        dcc.Tab(label='Common Data Types', children=[
            dcc.Graph(figure=fig2),
            html.Div("This chart shows the most common types of compromised data. Hover over a bar to see details."),
            html.Div("With email addresses and passwords leading the way in exposed data types, this reinforces the importance of strong password policies, multi-factor authentication (MFA), and user education.\nAlso indicates to the average person why it's recommended to have a couple of junk email addresses, or using different passwords for each site")
        ]),
        dcc.Tab(label='Verification Status', children=[
            dcc.Graph(figure=fig4),
            html.Div("This pie chart shows the ratio of verified to unverified breaches."),
            html.Div("An unverified breach refers to a data breach where the authenticity of the source breach hasn't been fully confirmed, but the data itself appears legitimate enough to be included in the database."),
            html.Div("What it means: The site or service claimed to have been breached hasn't confirmed it (or may even deny it)."),
            html.Div("However, the leaked data (emails, passwords, etc.) seems real based on analysis (e.g., email verification, password formats, duplicates).")
        ])
    ]),

    html.Hr(),
    html.Div("Created by Norah Kuduk • April 2025", className="text-center text-muted")
], fluid=True)

# --- 5. Callback for Interactive Details ---
@app.callback(
    Output('breach-details', 'children'),
    Input('top-breaches-chart', 'clickData')
)
def display_breach_details(clickData):
    if clickData:
        title_clicked = clickData['points'][0]['y']
        breach = df[df['BreachTitle'] == title_clicked].iloc[0]
        return (
            f"Breach: {breach['BreachTitle']}\n"
            f"Breach Date: {breach['BreachDate'].date()}\n"
            f"Accounts Affected: {breach['AccountsAffected']:,}\n\n"
            f"Description:\n{breach['Description']}"
        )
    return "Click on a bar above to see breach details."

@app.callback(
    Output('top-breaches-year-chart', 'figure'),
    Input('breaches-over-time-chart', 'clickData')
)
def update_top_breaches_for_year(clickData):
    if clickData:
        year_clicked = clickData['points'][0]['x']
        top5 = df[df['Year'] == int(year_clicked)].sort_values(by='AccountsAffected', ascending=False).head(5)
        fig = px.bar(
            top5,
            x='AccountsAffected',
            y='BreachTitle',
            orientation='h',
            title=f'Top 5 Breaches in {year_clicked}',
            hover_data=['BreachDate']
        )
        return fig
    return px.bar(title='Click a year to view top breaches.')

@app.callback(
    Output('yearly-breach-details', 'children'),
    Input('top-breaches-year-chart', 'clickData')
)
def display_yearly_breach_details(clickData):
    if clickData:
        title_clicked = clickData['points'][0]['y']
        breach = df[df['BreachTitle'] == title_clicked].iloc[0]
        return (
            f"Breach: {breach['BreachTitle']}\n"
            f"Breach Date: {breach['BreachDate'].date()}\n"
            f"Accounts Affected: {breach['AccountsAffected']:,}\n\n"
            f"Description:\n{breach['Description']}"
        )
    return "Click on a breach to see details."

# --- 6. Run Server ---
if __name__ == '__main__':
    app.run(debug=True)

