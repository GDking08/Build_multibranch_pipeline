import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.linear_model import LogisticRegression
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# Load CSV file into a DataFrame
df = pd.read_csv("E:\ML\exnew.csv")

# Mapping categorical values to continuous values if needed
# df['Label'] = df['Label'].map({0: 'benign', 1: 'malicious'})

# Extract features (X) and target (y) from the DataFrame
X = df.drop(['Label', 'URL'], axis=1)  # Exclude non-numeric columns like 'URL'
y = df['Label']  # Target variable

# List of categorical columns to be one-hot encoded
categorical_cols = ['Domain_Reputation', 'Domain_Registrar', 'Favicon', 'SSL_Certificate']

# Define preprocessing steps with ColumnTransformer
preprocessor = ColumnTransformer(
    transformers=[
        ('onehot', OneHotEncoder(), categorical_cols),
    ],
    remainder='passthrough'
)

# Create the Logistic Regression model
log_reg_model = LogisticRegression(random_state=42)

# Create the pipeline with preprocessing and Logistic Regression
pipeline = Pipeline(steps=[
    ('preprocessor', preprocessor),
    ('log_reg', log_reg_model)
])

# Split the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Fit the pipeline (preprocessing and Logistic Regression) on training data
pipeline.fit(X_train, y_train)

# Predictions on the testing set
y_pred = pipeline.predict(X_test)

# Calculate accuracy
accuracy = accuracy_score(y_test, y_pred)
print("Accuracy:", accuracy)

# Classification report
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Confusion matrix
conf_matrix = confusion_matrix(y_test, y_pred)
print("\nConfusion Matrix:")
print(conf_matrix)
