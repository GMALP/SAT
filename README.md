# SAT
Security Alert Triage project, details in paper: 'Edge Based Graph Active Learning: A Case Study in Security
Alert Triage'

## DATASET Description
We collected discontinuous data for a total of fourteen weeks.
details as following:

### Alert_data  
#### alert_data.xlsx 
	   |-事件名称 : alert name		
	   |-确信度	: expert set
	   |-源IP :  	
	   |-源区域 : this field has been desensitized as required  
	   |-目的IP : 
	   |-目的区域 : this field has been desensitized as required  
	   |-等级 : rule set
	   |-次数		
	   |-攻击阶段		
	   |-情报IOC	
	   |-检测引擎	
	   |-timestamp	
	   |-目的端口	
	   |-目的端口是否为常用端口 : feature	
	   |-week_index : this field is used process data window index in project, it can be modified according timestamp as required.  
	   |-label
	   
	   
## docker run (linux environment)
### pull the image
docker pull arvssj/sat_project:0.01

#### usage
mkdir /home/results/
docker run -d --name test_run -v /home/results/:/Security_Alert_Triage_project/results/ docker_sat_run:v0.01

Please find the final results(figure and table) in '/home/results/' folder

## pycharm run (window environment)
git clone https://github.com/GMALP/SAT.git

#### 1. reference requirements
pip install -r requirements.txt --ignore-installed


#### 2. usage
python main.py


## other note
1. Due there are many comparison algorithms, the final running time is relatively long.

2. We will continue to optimize later. If you have any questions, please contact: arvilla@qq.com
