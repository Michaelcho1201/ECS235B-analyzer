#include <iostream>

struct Node {
    int value;
    Node* next;
};

int main()
{

    Node* head = nullptr;
    std::cout << head->value;  
	

	if(head == nullptr)
	{
		std::cout << head->value;
	}
	
	Node* head2 = nullptr;
	
	while(head2 == nullptr)
	{
		std::cout << head2->value;
	}


	Node* head3 = nullptr;
	
	while(head2 == nullptr)
	{
		std::cout << head3->value;
	}
	
	Node* head4 = nullptr;
	if(head3 != nullptr)
	{
		std::cout << head3->value;
	}else{
		std::cout << head4->value;
	}
}

