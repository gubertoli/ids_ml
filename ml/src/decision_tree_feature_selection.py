from arff2pandas import a2p
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.feature_selection import SelectFromModel
import pandas as pd


# considering dataset, this def just return header-based features plus class
def dataset_header_features_only(path):
	with open('../dataset/' + path) as f:
		df = a2p.load(f)
		# just using header-based features
		df1 = pd.concat([df.iloc[:,0:20], df.iloc[:, len(df.columns)-1]], axis=1)
	return df1

def main():
	# create a Pandas Dataframe with Training Dataset
	pd_train = dataset_header_features_only('probe_attack_known_train.arff')
	#pd_train.append(dataset_header_features_only('probe_known_service_content_train.arff'))
	#pd_train.append(dataset_header_features_only('probe_known_service_train.arff'))
	d = {'attack': 1, 'normal': 0}
	pd_train['class@{normal,attack}'] = pd_train['class@{normal,attack}'].map(d)
	X = pd_train[list(pd_train.columns[:len(pd_train.columns)-1])]
	Y = pd_train['class@{normal,attack}']
	
	
	# create a Pandas Dataframe with Validation Dataset
	pd_validation = dataset_header_features_only('probe_attack_known_validation.arff')
	#pd_validation.append(dataset_header_features_only('probe_known_service_content_test.arff'))
	#pd_validation.append(dataset_header_features_only('probe_known_service_test.arff'))
	pd_validation['class@{normal,attack}'] = pd_validation['class@{normal,attack}'].map(d)
	X_test = pd_validation[list(pd_validation.columns[:len(pd_validation.columns)-1])]
	Y_test = pd_validation['class@{normal,attack}']

	clf = DecisionTreeClassifier()
	try:
		print(X.shape)
		clf = clf.fit(X, Y)
		print(accuracy_score(Y_test, clf.predict(X_test)))
		model = SelectFromModel(clf, prefit=True)
		feature_idx = model.get_support()
		feature_name = pd_train[list(pd_train.columns[:len(pd_train.columns)-1])].columns[feature_idx]
		print(feature_name)
		X = model.transform(X)
		print(X.shape)
		clf = clf.fit(X, Y)
	except ValueError as e:
		print(e)

	try:
		Y_prediction = clf.predict(X_test[feature_name])
		print(accuracy_score(Y_test, Y_prediction))
		print(classification_report(Y_test, Y_prediction))
	except ValueError as e:
		print(e)

if __name__ == "__main__":
	main()