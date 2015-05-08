/*
 *  tdsplaytree.h
 *  netent
 *
 *  Created by mjw Fall 2001.
 *  Copyright 2001. All rights reserved.
 *  Licensed under the GPL
 *
 */



template <class TYPE>
struct tree_node
{
	TYPE Data;
	
	tree_node * Left;
	tree_node * Right;
};



template <class TYPE>
class TD_Splay_Tree
{
	
private:
	
	tree_node <TYPE> * Root;
	int (*Cmp) (const TYPE &, const TYPE &);
	
	void Rotate_Right(tree_node <TYPE> * & Ptr, tree_node <TYPE> *& Save);
	void Rotate_Left(tree_node <TYPE> * & Ptr, tree_node <TYPE> *& Save);
	void Rotate_Double_Right(tree_node <TYPE> * & Ptr, tree_node <TYPE> * &Save);
	void Rotate_Double_Left(tree_node <TYPE> * & Ptr, tree_node <TYPE> * &Save);
	
	TYPE * Splay(const TYPE &, tree_node <TYPE> *); 
	tree_node <TYPE> * LeftTreeSave;
	tree_node <TYPE> * RightTreeSave;
	void ReMakeTree();
	
	void OrderPrint(tree_node <TYPE> * );
	void PrePrint(tree_node <TYPE> *);
	void Remove (tree_node <TYPE> *);
	void Decon(tree_node <TYPE> *);
	void Copy(tree_node <TYPE> * &Ptr, const tree_node <TYPE> * Source);
	void WalkTree(tree_node <TYPE> *, vector<TYPE *> *);
	
	int Num_Nodes;
	
public:
	
	TD_Splay_Tree( int (* Compare) (const TYPE &, const TYPE &));
	TD_Splay_Tree (const TD_Splay_Tree <TYPE> & Source);
	
	~TD_Splay_Tree();
	void In_Order_Print();
	void Pre_Order_Print();
	
	void Delete(const TYPE &);
	void Insert(const TYPE &);
	TYPE* Find(const TYPE &);
	TYPE* Find_Or_Insert(const TYPE &);
	vector<TYPE *> * GetTreeVector();
	int Get_Size();
	
};//end of TD_Splay_Tree


/*********************Constructors *********************************/
template <class TYPE>
TD_Splay_Tree <TYPE> :: 
TD_Splay_Tree( int (* Compare) (const TYPE &, const TYPE &))
{
	Root = NULL;
	Cmp = Compare;
	
}




template <class TYPE>
TD_Splay_Tree <TYPE> :: TD_Splay_Tree (const TD_Splay_Tree <TYPE> & Source)
{
	
	Root = NULL;
	Cmp = Source.Cmp;
	
	Copy(Root, Source.Root);
	
}



template <class TYPE>
void TD_Splay_Tree <TYPE> :: Copy(tree_node <TYPE> *& Ptr, const tree_node <TYPE> * Source)
{
	
	if(Source != NULL)
    {
		Ptr = new tree_node <TYPE>;
		
		if(Ptr == NULL)
		{
			cerr <<"ERROR: Out of Memory!"<<endl;
			exit(-1);
		}
		
		Ptr -> Data = Source -> Data;
		
		Copy(Ptr -> Left, Source -> Left);
		Copy(Ptr -> Right, Source -> Right);
		
    }
	
}




/********************* deconstructor *********************************/
template <class TYPE>
TD_Splay_Tree <TYPE> :: ~TD_Splay_Tree()
{  
	
	Decon(Root);
	
	delete Root;
	Root = NULL;
}


template <class TYPE>
void TD_Splay_Tree <TYPE> :: Decon(tree_node <TYPE> * Ptr)
{
	if(Ptr -> Left != NULL)
		Decon(Ptr -> Left);
	
	if(Ptr -> Right != NULL)
		Decon(Ptr -> Right);
	
	if(Ptr != Root)
    {
		delete Ptr;
		Ptr = NULL;
    }
	
}


/************************** Delete ******************************/
template <class TYPE>
void TD_Splay_Tree <TYPE> :: Delete(const TYPE & Val)
{
	
	tree_node <TYPE> * AuxL, * Temp, *AuxR, *Aux;
	Temp = Aux = AuxL = AuxR = NULL;
	
	TYPE * IsPresent;
	
	if(Root == NULL)
		return;
	
	
	
	IsPresent = Find(Val);
	
	if(IsPresent == NULL)
		return;
	
	Num_Nodes--;
	
	if(Root -> Left != NULL && Root -> Right != NULL)
    {
		
		Temp = Root -> Right;
		
		while(Temp -> Left != NULL)
        {
			Aux = Temp;
			Temp = Temp -> Left;
        }
		
		Aux -> Left = Temp -> Right;
		
		AuxL = Root -> Left;
		AuxR = Root -> Right;
		
		delete Root;
		
		Root = Temp;
		Temp = Root -> Right;
		
		Root -> Left = AuxL;
		Root -> Right = AuxR;      
    }
	
	else if(Root -> Left == NULL)
    {
		Temp = Root -> Right;
		delete Root;
		
		Root = Temp;
    }
	
	else
    {
		Temp = Root -> Left;
		delete Root;
		
		Root = Temp;
    }
	
	
	
	
}//end of Delete


/******************** Find_Or_Insert ****************************/
//Returns a Ptr to the data if found
//Returns null if not found, but inserts

template <class TYPE>
TYPE* TD_Splay_Tree <TYPE> :: Find_Or_Insert (const TYPE & Val)
{
	
	TYPE * Ptr;
	
	if( (Ptr = Find(Val) ) == NULL)
    {
		Insert(Val);  
		return NULL;
    }
	
	else
		return (Ptr);
	
	
}//end of Find_Or_Insert




/********************* Splay **************************************/
template <class TYPE>
TYPE* TD_Splay_Tree <TYPE> :: Splay (const TYPE & Val, tree_node <TYPE> * Root)
{
	int Cmp_Val;
	bool Found = false;
	
	tree_node <TYPE> * Left, * Right;
	tree_node <TYPE> Save_Tree;
	Save_Tree.Left = Save_Tree.Right = NULL;
	Left = Right = &Save_Tree;
	
	if(Root == NULL)
		return NULL;
	
	
	while (!Found )
    {  
		Cmp_Val = Cmp (Val, Root -> Data);
		
		if(Cmp_Val == 0)
		{
			Found = true;
			break;
		}
		
		else if (Cmp_Val < 0) 
		{
			if (Root -> Left == NULL)
				break;
			
			
			Cmp_Val = Cmp(Val, Root -> Left -> Data);
			
			if(Cmp_Val == 0)
			{
				Rotate_Right(Root, Right);
				Found = true;
				break;
			}
			
			if( Cmp_Val < 0) 
			{ 
				if (Root -> Left -> Left == NULL)
				{
					Rotate_Right(Root, Right);
					break;
				}
				
				Rotate_Double_Right(Root, Right);
			}
			
			else //Zig-Zag case .. left then right
			{ 
				
				if(Root -> Left -> Right == NULL)
				{
					Rotate_Right(Root, Right);
					break;
				}
				
				Rotate_Left(Root -> Left, Left);
				Rotate_Right(Root, Right);
			}
		}
		
		else 
		{
			if (Root -> Right == NULL)
				break;	  
			
			Cmp_Val = Cmp(Val, Root -> Right -> Data);
			
			if(Cmp_Val == 0)
			{
				Rotate_Left(Root, Left);
				Found = true;
				break;
			}
			
			if( Cmp_Val > 0) //maybe switch to < 12-8-01 
			{ 
				if (Root -> Right -> Right == NULL)
				{
					Rotate_Left(Root, Left);
					break;
				}
				
				Rotate_Double_Left(Root, Left);
			}
			
			else //Zig-Zag case .. left then right
			{ 
				if(Root ->Right -> Left == NULL)
				{
					Rotate_Left(Root, Left);
					break;
				}
				Rotate_Right(Root -> Right, Right);
				Rotate_Left(Root, Left);
				
			}
		}
    }
	
	
	//Remake the tree
	
	
	
	if (Root == NULL)
    {
		if (Save_Tree.Right != NULL && Save_Tree.Left != NULL) //both not empty
		{ 
			Root = Right;
			Right = Root -> Right;
			Root -> Right = Save_Tree.Left;
			Left -> Right = Root -> Left;
			Root -> Left = Save_Tree.Right;
		}
		
		else if(Save_Tree.Right == NULL) 
		{
			Root = Save_Tree.Left;
			Left -> Right = NULL;
		}
		
		else //
		{
			Root = Save_Tree.Right;
			Right -> Left = NULL;
		}
    }  
	
	else //Root != NULL
    {
		
		Left -> Right = Root -> Left;
		Root -> Left = Save_Tree.Right;
		
		Right -> Left = Root -> Right;
		Root -> Right = Save_Tree.Left;
    }
	
	if(  Cmp (Val, Root -> Data) == 0)
		Found = true;
	
	if (Found == true)
		return  &(Root -> Data);  
	else 
		return NULL;
	
	
}//end of Splay







/********************* Find **************************************/
template <class TYPE>
TYPE* TD_Splay_Tree <TYPE> :: Find (const TYPE & Val)
{
	int Cmp_Val;
	bool Found = false;
	
	tree_node <TYPE> * Left, * Right;
	tree_node <TYPE> Save_Tree;
	Save_Tree.Left = Save_Tree.Right =NULL;
	Left = Right = &Save_Tree;
	
	if(Root == NULL)
		return NULL;
	
	
	while (!Found  )
    {  
		Cmp_Val = Cmp (Val, Root -> Data);
		
		if(Cmp_Val == 0)
		{
			Found = true;
			break;
		}
		
		else if (Cmp_Val < 0) 
		{
			if (Root -> Left == NULL)
				break;
			
			
			Cmp_Val = Cmp(Val, Root -> Left -> Data);
			
			if(Cmp_Val == 0)
			{
				Rotate_Right(Root, Right);
				Found = true;
				break;
			}
			
			if( Cmp_Val < 0) 
			{ 
				if (Root -> Left -> Left == NULL)
				{
					Rotate_Right(Root, Right);
					break;
				}
				
				Rotate_Double_Right(Root, Right);
			}
			
			else //Zig-Zag case .. left then right
			{ 
				
				if(Root -> Left -> Right == NULL)
				{
					Rotate_Right(Root, Right);
					break;
				}
				
				Rotate_Left(Root -> Left, Left);
				Rotate_Right(Root, Right);
			}
		}
		
		else 
		{
			if (Root -> Right == NULL)
				break;	  
			
			Cmp_Val = Cmp(Val, Root -> Right -> Data);
			
			if(Cmp_Val == 0)
			{
				Rotate_Left(Root, Left);
				Found = true;
				break;
			}
			
			if( Cmp_Val > 0) //maybe switch to < 12-8-01 
			{ 
				if (Root -> Right -> Right == NULL)
				{
					Rotate_Left(Root, Left);
					break;
				}
				
				Rotate_Double_Left(Root, Left);
			}
			
			else //Zig-Zag case .. left then right
			{ 
				if(Root ->Right -> Left == NULL)
				{
					Rotate_Left(Root, Left);
					break;
				}
				Rotate_Right(Root -> Right, Right);
				Rotate_Left(Root, Left);
				
			}
		}
    }
	
	
	//Remake the tree
	
	
	
	if (Root == NULL)
    {
		if (Save_Tree.Right != NULL && Save_Tree.Left != NULL) //both not empty
		{ 
			Root = Right;
			Right = Root -> Right;
			Root -> Right = Save_Tree.Left;
			Left -> Right = Root -> Left;
			Root -> Left = Save_Tree.Right;
		}
		
		else if(Save_Tree.Right == NULL) 
		{
			Root = Save_Tree.Left;
			Left -> Right = NULL;
		}
		
		else //
		{
			Root = Save_Tree.Right;
			Right -> Left = NULL;
		}
    }  
	
	else //Root != NULL
    {
		
		Left -> Right = Root -> Left;
		Root -> Left = Save_Tree.Right;
		
		Right -> Left = Root -> Right;
		Root -> Right = Save_Tree.Left;
    }
	
	if(  Cmp (Val, Root -> Data) == 0)
		Found = true;
	
	if (Found == true)
		return  &(Root -> Data);  
	else 
		return NULL;
	
	
}//end of Find




/********************** Insert ************************************/
template <class TYPE>
void TD_Splay_Tree <TYPE> :: Insert (const TYPE & Val)
{
	int Cmp_Val;
	tree_node <TYPE> * Left, * Right;
	
	tree_node <TYPE> Save_Tree;
	Save_Tree.Left = Save_Tree.Right = NULL;
	Left= Right = &Save_Tree;
	
	
	tree_node <TYPE> * Ptr;
	Ptr = new tree_node <TYPE>;
	
	if(Ptr == NULL)
    {
		cerr<<"ERROR: No Memory!"<<endl;
		exit(-1);
    }
	
	Ptr -> Data = Val;
	Ptr -> Left = Ptr -> Right = NULL;
	
	
	while ( Root != NULL )
    {  
		Cmp_Val = Cmp (Val, Root -> Data);
		
		if (Cmp_Val <= 0) 
		{
			
			if (Root -> Left == NULL)
			{      
				Rotate_Right(Root, Right);
			}
			
			else if( (Cmp_Val = Cmp(Val, Root -> Left -> Data) ) <= 0) 
			{ 
				Rotate_Double_Right(Root, Right);
			}
			
			else //Zig-Zag case .. left then right
			{ 
				Rotate_Left(Root -> Left, Left);
				Rotate_Right(Root, Right);
				
			}	      	      
		}
		
		
		else 
		{
			
			if (Root -> Right == NULL)
            {
				Rotate_Left(Root, Left);
            }
			
			
			else if (  (Cmp_Val = Cmp(Val, Root -> Right ->  Data))  > 0)  
            { 
				Rotate_Double_Left(Root, Left);
            }
			
			else //Zig-Zag
            {
				Rotate_Right(Root -> Right, Right);
				Rotate_Left(Root, Left);
				
            }
		}
		
    }//end of while
	
	
	Root = Ptr;
	Left -> Right = NULL;
	Root -> Left = Save_Tree.Right;
	Right -> Left = NULL;
	Root -> Right = Save_Tree.Left;
	
	Num_Nodes++;
	
}//end of Insert




template <class TYPE>
void TD_Splay_Tree <TYPE> :: Rotate_Left(tree_node <TYPE> * & Ptr, tree_node <TYPE> *& Save)
{
	Save -> Right = Ptr;
	Save = Ptr;
	Ptr = Ptr -> Right;
}

template <class TYPE>
void TD_Splay_Tree <TYPE> :: 
Rotate_Double_Left (tree_node <TYPE> * & Ptr, tree_node <TYPE> * & Save)
{
	tree_node <TYPE> * Temp; 
	
	Temp = Ptr -> Right;
	Save -> Right = Temp;
	Save = Temp;
	Ptr -> Right = Temp -> Left;
	Temp -> Left = Ptr;
	Ptr = Temp -> Right;
	
}

template <class TYPE>
void TD_Splay_Tree <TYPE> :: 
Rotate_Right (tree_node <TYPE> * & Ptr, tree_node <TYPE> * & Save)
{
	Save -> Left = Ptr;
	Save = Ptr;
	Ptr = Ptr -> Left;
	
	return;
}

template <class TYPE>
void TD_Splay_Tree <TYPE> :: Rotate_Double_Right(tree_node <TYPE> * & Ptr, tree_node <TYPE> *& Save)
{
	tree_node <TYPE> * Temp;
	
	Temp = Ptr -> Left;
	Save -> Left = Temp;
	Save = Temp;
	Ptr -> Left = Temp -> Right;
	Temp -> Right = Ptr;
	Ptr = Temp -> Left;
}





template <class TYPE>
void TD_Splay_Tree <TYPE> :: Pre_Order_Print()
{
	
	tree_node <TYPE> * Ptr;
	
	Ptr = Root;
	PrePrint(Ptr);
} 


template <class TYPE>
void TD_Splay_Tree <TYPE> :: In_Order_Print()
{
	tree_node <TYPE> * Ptr;
	
	Ptr = Root;
	OrderPrint(Ptr);
}

template <class TYPE>
int TD_Splay_Tree <TYPE> :: Get_Size()
{
	return Num_Nodes;
}

template <class TYPE>
void TD_Splay_Tree <TYPE> :: PrePrint(tree_node <TYPE> * Ptr)
{
	if (Ptr != NULL)
    {
		cout << Ptr -> Data <<endl;
		PrePrint(Ptr -> Left);
		PrePrint(Ptr -> Right);
    }
	
	
}

template <class TYPE>
void TD_Splay_Tree <TYPE> :: OrderPrint(tree_node <TYPE> * Ptr)
{
	if (Ptr != NULL)
    {
		OrderPrint(Ptr -> Left);
		cout<< Ptr -> Data<<endl;
		OrderPrint(Ptr -> Right);
    }
}

template <class TYPE>
vector <TYPE *> * TD_Splay_Tree <TYPE> :: GetTreeVector()
{
	//declare it as a pointer so the memory is on the heap and not trashed
	vector <TYPE *> * v = new vector <TYPE *>;
	
	if(!v)
	{
		cerr << "vector malloc failed. might want to bail" <<endl;
	}
	
	tree_node <TYPE> * Ptr;
	
	Ptr = Root;
	WalkTree(Ptr, v);
	
	return v;
	
}

template <class TYPE>
void TD_Splay_Tree <TYPE> :: WalkTree(tree_node <TYPE> * Ptr, vector<TYPE *>* v)
{
	if (Ptr != NULL)
    {
		v->push_back(&Ptr->Data);
		WalkTree(Ptr -> Left, v);
		WalkTree(Ptr -> Right, v);

    }
	
}

